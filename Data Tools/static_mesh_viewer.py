"""Experimental read-only viewer for Pipeworks type-0 static meshes."""

from __future__ import annotations

import math
import importlib.util
import sys
import struct
import tkinter as tk
from dataclasses import dataclass
from pathlib import Path
from tkinter import ttk

try:
    from PIL import Image, ImageDraw, ImageTk
except Exception:
    Image = ImageDraw = ImageTk = None

try:
    import numpy as np
except Exception:
    np = None

try:
    vendor_dir = Path(__file__).resolve().parent.parent / "vendor"
    if vendor_dir.is_dir() and str(vendor_dir) not in sys.path:
        sys.path.insert(0, str(vendor_dir))
    import moderngl
except Exception:
    moderngl = None


_TEXTURE_INFO_CACHE = {}


def _load_ps2_static_mesh():
    path = Path(__file__).resolve().parent / "ps2_static_mesh.py"
    if not path.exists():
        return None
    spec = importlib.util.spec_from_file_location("gzbuildr_ps2_static_mesh_decoder", path)
    if spec is None or spec.loader is None:
        return None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


PS2_STATIC_MESH = _load_ps2_static_mesh()


class MeshDecodeError(ValueError):
    pass


@dataclass
class Mesh:
    vertices: list[tuple[float, float, float]]
    faces: list[tuple[int, int, int]]
    decoder: str
    uvs: list[tuple[float, float]] | None = None
    face_colors: list[tuple[int, int, int]] | None = None
    face_textures: list[object] | None = None
    uv_faces: list[tuple[int, int, int]] | None = None
    face_materials: list[int | None] | None = None
    face_two_sided: list[bool] | None = None
    face_opacity: list[float] | None = None
    lines: list[tuple[int, int]] | None = None


def _u32(data: bytes, offset: int, endian: str) -> int:
    return struct.unpack_from(endian + "I", data, offset)[0]


def _finite_vertices(vertices):
    return bool(vertices) and all(math.isfinite(value) and abs(value) < 1.0e8 for vertex in vertices for value in vertex)


def _validate_mesh(mesh: Mesh) -> Mesh:
    if len(mesh.vertices) < 2 or (not mesh.faces and not mesh.lines):
        raise MeshDecodeError("No drawable geometry was found in this type-0 pair.")
    if not _finite_vertices(mesh.vertices):
        raise MeshDecodeError("The decoded vertex stream contains invalid coordinates.")
    if any(min(face) < 0 or max(face) >= len(mesh.vertices) for face in mesh.faces):
        raise MeshDecodeError("The decoded face stream references vertices outside the resource.")
    if mesh.lines and any(min(line) < 0 or max(line) >= len(mesh.vertices) for line in mesh.lines):
        raise MeshDecodeError("The decoded line stream references vertices outside the resource.")
    spans = [max(axis) - min(axis) for axis in zip(*mesh.vertices)]
    if max(spans) <= 1.0e-7:
        raise MeshDecodeError("The decoded geometry has no visible extent.")
    return mesh


def _strip_faces(indices, markers=None):
    faces = []
    for index in range(len(indices) - 2):
        if markers is not None and not markers[index + 2]:
            continue
        tri = (indices[index], indices[index + 1], indices[index + 2])
        if index & 1:
            tri = (tri[1], tri[0], tri[2])
        if len(set(tri)) == 3:
            faces.append(tri)
    return faces


def _decode_ps2(main: bytes, resource: bytes) -> Mesh:
    candidates = []
    for offset in range(0, max(0, len(main) - 0x18 + 1), 4):
        count = _u32(main, offset, "<")
        stride = _u32(main, offset + 4, "<")
        fmt = _u32(main, offset + 8, "<")
        rel = _u32(main, offset + 0x10, "<")
        region_size = _u32(main, offset + 0x14, "<")
        if stride not in (0x10, 0x14, 0x18, 0x24, 0x28, 0x2C) or fmt not in (0x12, 0x102, 0x112, 0x116, 0x118, 0x142, 0x149, 0x152):
            continue
        if not (2 < count < 100000 and rel + count * 16 <= len(resource)):
            continue
        if region_size and region_size > len(resource) - rel:
            continue
        candidates.append((rel, count, stride, fmt))

    by_rel = {}
    for rel, count, stride, fmt in candidates:
        current = by_rel.get(rel)
        if current is None or count > current[0]:
            by_rel[rel] = (count, stride, fmt)
    vertices = []
    faces = []
    for rel, (count, stride, _fmt) in sorted(by_rel.items()):
        if _fmt == 0x12:
            stride = 0x10
        base = len(vertices)
        if rel + count * stride > len(resource):
            continue
        packet_vertices = [struct.unpack_from("<3f", resource, rel + index * stride) for index in range(count)]
        if not _finite_vertices(packet_vertices):
            continue
        side = rel + count * stride
        side_records = [resource[side + index * 4:side + index * 4 + 4] for index in range(count)]
        controls = [resource[rel + index * stride + 12:rel + index * stride + 16] for index in range(count)]
        control_flags = set(controls)
        if control_flags and control_flags.issubset({b"\0\0\0\0", b"\0\0\x80?"}):
            markers = [record == b"\0\0\x80?" for record in controls]
        elif stride == 0x10 and side + count * 4 <= len(resource):
            markers = [len(record) == 4 and record[3] != 0 for record in side_records]
        else:
            markers = None
        packet_faces = _strip_faces(list(range(count)), markers)
        vertices.extend(packet_vertices)
        faces.extend(tuple(base + value for value in face) for face in packet_faces)
    if not faces and len(main) >= 0x24:
        count = _u32(main, 0x20, "<")
        if 2 < count < 100000 and count * 16 <= len(resource):
            packet_vertices = [struct.unpack_from("<3f", resource, index * 16) for index in range(count)]
            markers = [resource[index * 16 + 12:index * 16 + 16] == b"\0\0\x80?" for index in range(count)]
            packet_faces = _strip_faces(list(range(count)), markers)
            if packet_faces and _finite_vertices(packet_vertices):
                vertices, faces = packet_vertices, packet_faces
    if not faces:
        raise MeshDecodeError("This PS2 type-0 descriptor layout is not decoded yet.")
    return _validate_mesh(Mesh(vertices, faces, "PS2 little-endian strips"))


def _gx_faces(op, indices):
    primitive = op & 0xF8
    if primitive == 0x90:
        return [tuple(indices[i:i + 3]) for i in range(0, len(indices) - 2, 3)]
    if primitive == 0x98:
        return _strip_faces(indices)
    if primitive == 0xA0 and len(indices) >= 3:
        return [(indices[0], indices[i], indices[i + 1]) for i in range(1, len(indices) - 1)]
    if primitive == 0x80:
        result = []
        for i in range(0, len(indices) - 3, 4):
            result.extend(((indices[i], indices[i + 1], indices[i + 2]), (indices[i], indices[i + 2], indices[i + 3])))
        return result
    return []


def _decode_gx_line_records(resource: bytes, start: int, size: int, vertex_count: int, width: int):
    end = start + size
    position = start
    lines = []
    while position < end:
        op = resource[position]
        if op == 0:
            position += 1
            continue
        if (op & 0xF8) != 0xB0 or position + 3 > end:
            break
        count = struct.unpack_from(">H", resource, position + 1)[0]
        position += 3
        indices = []
        for _ in range(count):
            if position + width > end:
                return []
            index = resource[position]
            position += width
            if index >= vertex_count:
                return []
            indices.append(index)
        lines.extend((indices[index], indices[index + 1]) for index in range(len(indices) - 1))
    return lines


def _gx_descriptors(main: bytes, resource_size: int):
    found = []
    for offset in range(0, max(0, len(main) - 0x4C + 1), 4):
        attr_count = _u32(main, offset, ">")
        vertex_count = _u32(main, offset + 0x10, ">")
        fmt = _u32(main, offset + 0x18, ">")
        vertex_rel = _u32(main, offset + 0x20, ">")
        pairs = []
        if offset >= 8:
            pairs.append((_u32(main, offset - 8, ">"), _u32(main, offset - 4, ">")))
        if offset + 0x68 <= len(main):
            pairs.append((_u32(main, offset + 0x60, ">"), _u32(main, offset + 0x64, ">")))
        for draw_rel, draw_size in pairs:
            if attr_count not in (1, 2, 3, 4) or not (2 < vertex_count < 100000):
                continue
            if fmt not in (0x102, 0x112, 0x116):
                continue
            if not (0 <= vertex_rel < resource_size and 0 <= draw_rel < resource_size and 0 < draw_size <= resource_size - draw_rel):
                continue
            key = (vertex_rel, vertex_count, draw_rel, draw_size, attr_count)
            if key not in found:
                found.append(key)
    return found


def _decode_gx_records(resource: bytes, start: int, size: int, vertex_count: int, widths, index_component_size=None):
    end = start + size
    best = []
    for width in widths:
        position = start
        faces = []
        valid = True
        while position < end:
            op = resource[position]
            if op == 0:
                position += 1
                continue
            if (op & 0xF8) not in (0x80, 0x90, 0x98, 0xA0, 0xB0) or position + 3 > end:
                break
            count = struct.unpack_from(">H", resource, position + 1)[0]
            position += 3
            indices = []
            for _ in range(count):
                if position + width > end:
                    valid = False
                    break
                if index_component_size == 1:
                    index = resource[position]
                elif index_component_size == 2:
                    index = struct.unpack_from(">H", resource, position)[0]
                else:
                    index = resource[position] if width in (1, 2, 3, 4, 5) else struct.unpack_from(">H", resource, position)[0]
                if index >= vertex_count:
                    valid = False
                    break
                indices.append(index)
                position += width
            if not valid:
                break
            faces.extend(_gx_faces(op, indices))
        if valid and len(faces) > len(best):
            best = faces
    return best


def _decode_gx_records_with_uv(resource: bytes, start: int, size: int, vertex_count: int, attr_count: int, component_size: int):
    end = start + size
    position = start
    faces = []
    uv_faces = []
    while position < end:
        op = resource[position]
        if op == 0:
            position += 1
            continue
        if (op & 0xF8) not in (0x80, 0x90, 0x98, 0xA0, 0xB0) or position + 3 > end:
            break
        count = struct.unpack_from(">H", resource, position + 1)[0]
        position += 3
        corners = []
        for _ in range(count):
            attributes = []
            for _attribute in range(attr_count):
                if position + component_size > end:
                    return [], []
                value = resource[position] if component_size == 1 else struct.unpack_from(">H", resource, position)[0]
                attributes.append(value)
                position += component_size
            if attributes[0] >= vertex_count or attributes[-1] >= vertex_count:
                return [], []
            corners.append((attributes[0], attributes[-1]))
        corner_faces = _gx_faces(op, corners)
        faces.extend(tuple(corner[0] for corner in face) for face in corner_faces)
        uv_faces.extend(tuple(corner[1] for corner in face) for face in corner_faces)
    return faces, uv_faces


def _decode_gx_mixed_records(
    resource: bytes, start: int, size: int, vertex_count: int,
    secondary_uv=False, uv_count_limit=None, widths=None,
):
    """Decode older GameCube packets whose corners mix indices and direct GX attributes."""
    end = start + size
    best = ([], [], 0)
    for width in (widths if widths is not None else range(1, 17)):
        preferred_column = (
            width - 1 if widths is not None and (secondary_uv or width < 4)
            else width - 2 if widths is not None
            else 3 if secondary_uv else 2
        )
        uv_columns = range(1, width)
        for uv_column in uv_columns:
            position = start
            faces = []
            uv_faces = []
            valid = True
            while position < end:
                op = resource[position]
                if op == 0:
                    position += 1
                    continue
                if (op & 0xF8) not in (0x80, 0x90, 0x98, 0xA0, 0xB0) or position + 3 > end:
                    valid = False
                    break
                count = struct.unpack_from(">H", resource, position + 1)[0]
                position += 3
                corners = []
                for _ in range(count):
                    if position + width > end:
                        valid = False
                        break
                    corner = resource[position:position + width]
                    position += width
                    if corner[0] >= vertex_count:
                        valid = False
                        break
                    uv_index = corner[uv_column]
                    if uv_count_limit is not None and uv_index >= uv_count_limit:
                        valid = False
                        break
                    corners.append((corner[0], uv_index))
                if not valid:
                    break
                for face in _gx_faces(op, corners):
                    position_face = tuple(corner[0] for corner in face)
                    if len(set(position_face)) < 3:
                        continue
                    faces.append(position_face)
                    uv_faces.append(tuple(corner[1] for corner in face))
            unique_positions = len({index for face in faces for index in face})
            unique_uvs = len({index for face in uv_faces for index in face})
            score = (
                len(faces) * 10000 + unique_positions * 100 + unique_uvs * 10
                - abs(uv_column - preferred_column)
            )
            if valid and score > best[2]:
                best = (faces, uv_faces, score)
    return best[0], best[1]


def _decode_gx_direct_uv_records(resource: bytes, start: int, size: int, vertex_count: int):
    """Decode GameCube corners containing direct float UVs and indexed/direct normals."""
    end = start + size
    best = ([], [], [])
    for corner_width, uv_offset in ((10, 2), (11, 2), (11, 3), (18, 2), (18, 10), (21, 13)):
        position = start
        faces = []
        uv_faces = []
        uvs = []
        valid = True
        while position < end:
            op = resource[position]
            if op == 0:
                position += 1
                continue
            if (op & 0xF8) not in (0x80, 0x90, 0x98, 0xA0, 0xB0) or position + 3 > end:
                valid = False
                break
            count = struct.unpack_from(">H", resource, position + 1)[0]
            position += 3
            corners = []
            for _ in range(count):
                if position + corner_width > end:
                    valid = False
                    break
                vertex_index = resource[position]
                uv = struct.unpack_from(">2f", resource, position + uv_offset)
                if vertex_index >= vertex_count or not all(math.isfinite(value) and abs(value) < 1.0e6 for value in uv):
                    valid = False
                    break
                uv_index = len(uvs)
                uvs.append(uv)
                corners.append((vertex_index, uv_index))
                position += corner_width
            if not valid:
                break
            for face in _gx_faces(op, corners):
                position_face = tuple(corner[0] for corner in face)
                if len(set(position_face)) < 3:
                    continue
                faces.append(position_face)
                uv_faces.append(tuple(corner[1] for corner in face))
        if valid and len(faces) > len(best[0]):
            best = (faces, uv_faces, uvs)
    return best


def _decode_gx_indexed16_records(
    resource: bytes, start: int, size: int, vertex_count: int,
    uv_count_limit=None, prefer_legacy_uv=False,
):
    """Decode indexed GameCube packets using declared byte/word/direct-normal combinations."""
    end = start + size
    best = ([], [])
    legacy_schemas = (
        (14, 1, 1, 1),  # position8, UV8, trailing direct attributes
        (15, 1, 1, 2),  # position8, UV16, trailing direct attributes
    )
    standard_schemas = (
        (4, 2, 1, 2),   # position8, normal8, UV16
        (4, 3, 2, 1),   # position16, normal8, UV8
        (5, 3, 2, 2),   # position16, normal8, UV16
        (5, 4, 2, 1),   # position16, normal16, UV8
        (6, 4, 2, 2),   # position16, normal16, UV16
        (14, 13, 1, 1), # position8, direct normal3f, UV8
        (15, 13, 1, 2), # position8, direct normal3f, UV16
    )
    schemas = legacy_schemas + standard_schemas if prefer_legacy_uv else standard_schemas
    for corner_width, uv_offset, position_size, uv_size in schemas:
        position = start
        faces = []
        uv_faces = []
        valid = True
        while position < end:
            op = resource[position]
            if op == 0:
                position += 1
                continue
            if (op & 0xF8) not in (0x80, 0x90, 0x98, 0xA0, 0xB0) or position + 3 > end:
                valid = False
                break
            count = struct.unpack_from(">H", resource, position + 1)[0]
            position += 3
            corners = []
            for _ in range(count):
                if position + corner_width > end:
                    valid = False
                    break
                vertex_index = (
                    resource[position] if position_size == 1
                    else struct.unpack_from(">H", resource, position)[0]
                )
                uv_index = (
                    resource[position + uv_offset] if uv_size == 1
                    else struct.unpack_from(">H", resource, position + uv_offset)[0]
                )
                position += corner_width
                if vertex_index >= vertex_count or (uv_count_limit is not None and uv_index >= uv_count_limit):
                    valid = False
                    break
                corners.append((vertex_index, uv_index))
            if not valid:
                break
            for face in _gx_faces(op, corners):
                position_face = tuple(corner[0] for corner in face)
                if len(set(position_face)) < 3:
                    continue
                faces.append(position_face)
                uv_faces.append(tuple(corner[1] for corner in face))
        if valid and len(faces) > len(best[0]):
            best = (faces, uv_faces)
    return best


def _decode_gx_wii(main: bytes, resource: bytes, material_options=None) -> Mesh:
    static_descriptors = []
    for offset in range(0, max(0, len(main) - 0x38 + 1), 4):
        record_count = _u32(main, offset, ">")
        marker = _u32(main, offset + 4, ">")
        draw_rel = _u32(main, offset + 8, ">")
        draw_size = _u32(main, offset + 0x0C, ">")
        attr_count = _u32(main, offset + 0x10, ">")
        count = _u32(main, offset + 0x20, ">")
        stride = _u32(main, offset + 0x24, ">")
        fmt = _u32(main, offset + 0x28, ">")
        rel = _u32(main, offset + 0x30, ">")
        size = _u32(main, offset + 0x34, ">")
        if not (1 <= attr_count <= 6 and 12 <= stride <= 128 and stride % 4 == 0):
            continue
        if fmt == 0:
            continue
        if not (2 < count < 100000 and size == count * stride and rel + size <= len(resource)):
            continue
        if not (0 <= draw_rel < rel and 0 < draw_size <= rel - draw_rel and draw_rel + draw_size == rel):
            continue
        index_component_size = 2 if marker == 0x10 else 1 if marker == 0x08 else 0
        index_width = attr_count * index_component_size
        if not (1 <= index_width <= 12):
            continue
        static_descriptors.append((
            draw_rel, draw_size, rel, count, stride, index_width,
            index_component_size, record_count, fmt,
        ))

    if static_descriptors:
        vertices = []
        faces = []
        lines = []
        uvs = []
        uv_faces = []
        face_materials = []
        surface_count = _u32(main, 0x10, ">") if len(main) >= 0x14 else 0
        material_ids = []
        for surface_index in range(min(surface_count, 1024)):
            material_offset = 0x36 + surface_index * 0x60
            if material_offset + 2 > len(main):
                break
            material_ids.append(struct.unpack_from(">H", main, material_offset)[0])
        for descriptor_index, descriptor in enumerate(sorted(set(static_descriptors))):
            draw_rel, draw_size, rel, count, stride, index_width, index_component_size, _record_count, fmt = descriptor
            packet_vertices = [struct.unpack_from(">3f", resource, rel + index * stride) for index in range(count)]
            packet_normals = (
                [struct.unpack_from(">3f", resource, rel + index * stride + 12) for index in range(count)]
                if stride >= 24 else None
            )
            material_id = material_ids[descriptor_index] if descriptor_index < len(material_ids) else None
            material_option = material_options.get(material_id, {}) if isinstance(material_options, dict) else {}
            secondary_uv = fmt == 0x252 and int(material_option.get("uv_set", 0)) == 1
            uv_offset = 36 if secondary_uv else 28 if fmt in (0x152, 0x252) and stride >= 36 else stride - 8
            packet_uvs = (
                [struct.unpack_from(">2f", resource, rel + index * stride + uv_offset) for index in range(count)]
                if index_width // index_component_size > 1 and stride >= 20 else []
            )
            if fmt == 0x252 and secondary_uv:
                packet_uvs = [(u, 1.0 - v) for u, v in packet_uvs]
            packet_faces, packet_uv_faces = _decode_gx_records_with_uv(
                resource, draw_rel, draw_size, count, index_width // index_component_size, index_component_size
            )
            if packet_faces and _finite_vertices(packet_vertices):
                oriented_faces = []
                oriented_uv_faces = []
                for face, uv_face in zip(packet_faces, packet_uv_faces):
                    a, b, c = (packet_vertices[index] for index in face)
                    ab = (b[0]-a[0], b[1]-a[1], b[2]-a[2])
                    ac = (c[0]-a[0], c[1]-a[1], c[2]-a[2])
                    geometric = (
                        ab[1]*ac[2] - ab[2]*ac[1],
                        ab[2]*ac[0] - ab[0]*ac[2],
                        ab[0]*ac[1] - ab[1]*ac[0],
                    )
                    normal = (
                        tuple(sum(packet_normals[index][axis] for index in face) for axis in range(3))
                        if packet_normals is not None else None
                    )
                    if normal is not None and sum(geometric[axis] * normal[axis] for axis in range(3)) < 0.0:
                        face = (face[0], face[2], face[1])
                        uv_face = (uv_face[0], uv_face[2], uv_face[1])
                    oriented_faces.append(face)
                    oriented_uv_faces.append(uv_face)
                packet_faces = oriented_faces
                packet_uv_faces = oriented_uv_faces
                base = len(vertices)
                vertices.extend(packet_vertices)
                if packet_uvs:
                    uvs.extend(packet_uvs)
                faces.extend(tuple(base + value for value in face) for face in packet_faces)
                if packet_uvs:
                    uv_faces.extend(tuple(base + value for value in face) for face in packet_uv_faces)
                face_materials.extend([material_id] * len(packet_faces))
        if faces:
            valid_uvs = (
                uvs if len(uvs) == len(vertices)
                and all(math.isfinite(value) and abs(value) < 1.0e6 for uv in uvs for value in uv)
                else None
            )
            return _validate_mesh(Mesh(
                vertices, faces, "GameCube/Wii GX static display lists", valid_uvs,
                uv_faces=uv_faces if len(uv_faces) == len(faces) else None,
                face_materials=face_materials,
            ))

    raise MeshDecodeError("This Wii type-0 GX descriptor layout is not decoded yet.")


def _decode_gx_gamecube(main: bytes, resource: bytes, material_options=None) -> Mesh:
    legacy_descriptors = []
    for fmt_offset in range(0x20, max(0x20, len(main) - 0x2C), 4):
        if _u32(main, fmt_offset, ">") not in (0x2, 0x12, 0x42, 0x62, 0x102, 0x112, 0x116, 0x212):
            continue
        draw_rel = _u32(main, fmt_offset - 0x20, ">")
        draw_size = _u32(main, fmt_offset - 0x1C, ">")
        count = _u32(main, fmt_offset - 8, ">")
        rel = _u32(main, fmt_offset + 8, ">")
        primary_uv_rel = _u32(main, fmt_offset + 0x20, ">")
        uv_data_end_rel = _u32(main, fmt_offset + 0x24, ">")
        if not (2 < count < 100000 and rel + count * 12 <= len(resource)):
            continue
        if not (0 <= draw_rel < rel and 0 < draw_size <= rel - draw_rel):
            continue
        legacy_descriptors.append((
            draw_rel, draw_size, rel, count, primary_uv_rel, uv_data_end_rel,
            _u32(main, fmt_offset, ">"), _u32(main, fmt_offset - 0x18, ">"),
        ))

    if legacy_descriptors:
        known_materials = set(material_options) if isinstance(material_options, dict) else set()
        material_ids = []
        if known_materials:
            surface_count = _u32(main, 0, ">") if len(main) >= 4 else 0
            for surface_index in range(min(surface_count, 1024)):
                material_offset = 0x84 + surface_index * 0x7C
                if material_offset + 2 > len(main):
                    break
                candidate = struct.unpack_from(">H", main, material_offset)[0]
                if candidate in known_materials:
                    material_ids.append(candidate)
        vertices = []
        faces = []
        lines = []
        uvs = []
        uv_faces = []
        face_materials = []
        for descriptor_index, descriptor in enumerate(sorted(set(legacy_descriptors))):
            draw_rel, draw_size, rel, count, primary_uv_rel, uv_data_end_rel, fmt, attr_width = descriptor
            packet_vertices = [struct.unpack_from(">3f", resource, rel + index * 12) for index in range(count)]
            material_id = material_ids[descriptor_index] if descriptor_index < len(material_ids) else None
            material_option = material_options.get(material_id, {}) if isinstance(material_options, dict) else {}
            prefer_legacy_uv = bool(material_option.get("legacy_uv"))
            secondary_uv = int(material_option.get("uv_set", 0)) == 1
            uv_count_limit = (
                (uv_data_end_rel - primary_uv_rel) // 8
                if uv_data_end_rel > primary_uv_rel else None
            )
            direct_faces, direct_uv_faces, direct_packet_uvs = _decode_gx_direct_uv_records(
                resource, draw_rel, draw_size, count
            )
            if (resource[draw_rel] & 0xF8) == 0xB0:
                packet_lines = _decode_gx_line_records(resource, draw_rel, draw_size, count, attr_width)
                if packet_lines and _finite_vertices(packet_vertices):
                    base_vertex = len(vertices)
                    vertices.extend(packet_vertices)
                    lines.extend((base_vertex + start, base_vertex + end) for start, end in packet_lines)
                continue
            indexed_faces, indexed_uv_faces = _decode_gx_mixed_records(
                resource, draw_rel, draw_size, count, secondary_uv, uv_count_limit,
                widths=(attr_width,) if 1 <= attr_width <= 16 else None,
            )
            if not indexed_faces:
                indexed_faces, indexed_uv_faces = _decode_gx_indexed16_records(
                    resource, draw_rel, draw_size, count, uv_count_limit, prefer_legacy_uv
                )
            if direct_faces and len(direct_faces) >= len(indexed_faces):
                packet_faces, packet_uv_faces = direct_faces, direct_uv_faces
            else:
                packet_faces, packet_uv_faces = indexed_faces, indexed_uv_faces
                direct_packet_uvs = []
            if not packet_faces:
                # Keep compact geometry when color or normal bytes occupy UV columns.
                packet_faces, packet_uv_faces = _decode_gx_mixed_records(
                    resource, draw_rel, draw_size, count, secondary_uv, None
                )
            if not packet_faces and fmt == 0x2 and uv_data_end_rel <= primary_uv_rel:
                packet_faces = _decode_gx_records(
                    resource, draw_rel, draw_size, count, (1,), index_component_size=1
                )
                packet_uv_faces = [(0, 0, 0)] * len(packet_faces)
            if not packet_faces or not _finite_vertices(packet_vertices):
                continue
            uv_count = max(index for face in packet_uv_faces for index in face) + 1
            uv_rel = primary_uv_rel
            uv_start = rel + uv_rel
            packet_uvs = direct_packet_uvs
            if not packet_uvs and (
                uv_data_end_rel > uv_rel
                and uv_rel > 0
                and uv_start + uv_count * 8 <= len(resource)
            ):
                packet_uvs = [struct.unpack_from(">2f", resource, uv_start + index * 8) for index in range(uv_count)]
            elif (
                not secondary_uv
                and uv_data_end_rel > primary_uv_rel
                and (uv_data_end_rel - primary_uv_rel) // 8 >= count
                and uv_start + count * 8 <= len(resource)
            ):
                packet_uvs = [struct.unpack_from(">2f", resource, uv_start + index * 8) for index in range(count)]
                packet_uv_faces = packet_faces
            base_vertex = len(vertices)
            base_uv = len(uvs)
            vertices.extend(packet_vertices)
            faces.extend(tuple(base_vertex + index for index in face) for face in packet_faces)
            if packet_uvs:
                uvs.extend(packet_uvs)
                uv_faces.extend(tuple(base_uv + index for index in face) for face in packet_uv_faces)
                face_materials.extend([material_id] * len(packet_faces))
            else:
                uvs.append((0.0, 0.0))
                uv_faces.extend([(base_uv, base_uv, base_uv)] * len(packet_faces))
                face_materials.extend([material_id] * len(packet_faces))
        if faces or lines:
            valid_uvs = uvs if uvs and all(math.isfinite(value) and abs(value) < 1.0e6 for uv in uvs for value in uv) else None
            return _validate_mesh(Mesh(
                vertices, faces, "GameCube GX legacy display lists", valid_uvs,
                uv_faces=uv_faces if valid_uvs is not None and len(uv_faces) == len(faces) else None,
                face_materials=face_materials,
                lines=lines or None,
            ))

    vertices = []
    faces = []
    for vertex_rel, count, draw_rel, draw_size, attr_count in _gx_descriptors(main, len(resource)):
        packet_faces = _decode_gx_records(resource, draw_rel, draw_size, count, (1, 2, 3, 4, 5, 6, 14, 16, 21, 22))
        if not packet_faces:
            continue
        packet_vertices = []
        for stride in (12, 24):
            if vertex_rel + count * stride > len(resource):
                continue
            values = [struct.unpack_from(">3f", resource, vertex_rel + index * stride) for index in range(count)]
            if _finite_vertices(values):
                packet_vertices = values
                break
        if not packet_vertices:
            continue
        base = len(vertices)
        vertices.extend(packet_vertices)
        faces.extend(tuple(base + value for value in face) for face in packet_faces)
    if not faces:
        raise MeshDecodeError("This GameCube type-0 GX descriptor layout is not decoded yet.")
    return _validate_mesh(Mesh(vertices, faces, "GameCube GX display lists"))


def decode_static_mesh(main: bytes, resource: bytes, big_endian: bool, material_options=None, gx_variant=None) -> Mesh:
    if not main or not resource:
        raise MeshDecodeError("The type-0 entry does not have both descriptor and resource data.")
    if not big_endian:
        if PS2_STATIC_MESH is not None:
            return PS2_STATIC_MESH.decode(main, resource, Mesh, _validate_mesh, MeshDecodeError)
        return _decode_ps2(main, resource)
    if gx_variant == "gamecube":
        return _decode_gx_gamecube(main, resource, material_options)
    return _decode_gx_wii(main, resource, material_options)


def combine_meshes(meshes: list[Mesh]) -> Mesh:
    if not meshes:
        raise MeshDecodeError("No static mesh parts were supplied.")
    vertices = []
    faces = []
    uvs = []
    face_colors = []
    face_textures = []
    uv_faces = []
    face_materials = []
    face_two_sided = []
    face_opacity = []
    lines = []
    has_uvs = all(mesh.uvs is not None for mesh in meshes)
    has_colors = all(mesh.face_colors is not None for mesh in meshes)
    has_textures = all(mesh.face_textures is not None for mesh in meshes)
    has_uv_faces = all(mesh.uv_faces is not None for mesh in meshes)
    has_materials = all(mesh.face_materials is not None for mesh in meshes)
    has_two_sided = all(mesh.face_two_sided is not None for mesh in meshes)
    has_opacity = all(mesh.face_opacity is not None for mesh in meshes)
    for mesh in meshes:
        base = len(vertices)
        uv_base = len(uvs)
        vertices.extend(mesh.vertices)
        faces.extend(tuple(base + index for index in face) for face in mesh.faces)
        if mesh.lines:
            lines.extend((base + start, base + end) for start, end in mesh.lines)
        if has_uvs:
            uvs.extend(mesh.uvs)
        if has_colors:
            face_colors.extend(mesh.face_colors)
        if has_textures:
            face_textures.extend(mesh.face_textures)
        if has_uv_faces:
            uv_faces.extend(tuple(uv_base + index for index in face) for face in mesh.uv_faces)
        if has_materials:
            face_materials.extend(mesh.face_materials)
        if has_two_sided:
            face_two_sided.extend(mesh.face_two_sided)
        if has_opacity:
            face_opacity.extend(mesh.face_opacity)
    decoder = meshes[0].decoder
    if len(meshes) > 1:
        decoder = f"{decoder} ({len(meshes)} connected parts)"
    return _validate_mesh(Mesh(
        vertices,
        faces,
        decoder,
        uvs if has_uvs else None,
        face_colors if has_colors else None,
        face_textures if has_textures else None,
        uv_faces if has_uv_faces else None,
        face_materials if has_materials else None,
        face_two_sided if has_two_sided else None,
        face_opacity if has_opacity else None,
        lines or None,
    ))


def transform_mesh(mesh: Mesh, matrix) -> Mesh:
    if matrix is None:
        return mesh
    vertices = []
    for x, y, z in mesh.vertices:
        vertices.append((
            matrix[0][0] * x + matrix[0][1] * y + matrix[0][2] * z + matrix[0][3],
            matrix[1][0] * x + matrix[1][1] * y + matrix[1][2] * z + matrix[1][3],
            matrix[2][0] * x + matrix[2][1] * y + matrix[2][2] * z + matrix[2][3],
        ))
    return Mesh(
        vertices, list(mesh.faces), mesh.decoder, mesh.uvs, mesh.face_colors,
        mesh.face_textures, mesh.uv_faces, mesh.face_materials, mesh.face_two_sided,
        mesh.face_opacity, list(mesh.lines) if mesh.lines else None,
    )


def texture_mesh(mesh: Mesh, texture) -> Mesh:
    if texture is None or mesh.uvs is None:
        return mesh
    material_map = texture if isinstance(texture, dict) else None
    default_texture = None if material_map is not None else texture
    colors = []
    face_textures = []
    face_two_sided = []
    face_opacity = []
    texture_cache = {}
    output_uvs = list(mesh.uvs)
    output_uv_faces = list(mesh.uv_faces or mesh.faces)
    vertex_normals = None
    if material_map is not None and any(
        material.get("environment_image") is not None for material in material_map.values()
    ):
        vertex_normals = [[0.0, 0.0, 0.0] for _ in mesh.vertices]
        for normal_face in mesh.faces:
            ax, ay, az = mesh.vertices[normal_face[0]]
            bx, by, bz = mesh.vertices[normal_face[1]]
            cx, cy, cz = mesh.vertices[normal_face[2]]
            ux, uy, uz = bx-ax, by-ay, bz-az
            vx, vy, vz = cx-ax, cy-ay, cz-az
            normal = (uy*vz-uz*vy, uz*vx-ux*vz, ux*vy-uy*vx)
            for vertex_index in normal_face:
                for axis in range(3):
                    vertex_normals[vertex_index][axis] += normal[axis]
        welded_normals = {}
        for vertex_index, position in enumerate(mesh.vertices):
            key = tuple(round(value, 5) for value in position)
            total = welded_normals.setdefault(key, [0.0, 0.0, 0.0])
            for axis in range(3):
                total[axis] += vertex_normals[vertex_index][axis]
        for vertex_index, position in enumerate(mesh.vertices):
            vertex_normals[vertex_index] = welded_normals[tuple(round(value, 5) for value in position)]
    for face_index, face in enumerate(mesh.faces):
        material_id = mesh.face_materials[face_index] if mesh.face_materials else None
        material = material_map.get(material_id) if material_map is not None else None
        image = material.get("image") if material else default_texture
        counterpart_roofs = material.get("counterpart_roofs") if material else None
        counterpart_roof = None
        if counterpart_roofs:
            face_positions = [
                tuple(round(value, 4) for value in mesh.vertices[index])
                for index in face
            ]
            counterpart_roof = counterpart_roofs.get(tuple(sorted(face_positions)))
            if counterpart_roof is not None:
                image = counterpart_roof["image"]
                exact_uv_face = []
                for position in face_positions:
                    exact_uv_face.append(len(output_uvs))
                    output_uvs.append(counterpart_roof["uv_by_position"][position])
                output_uv_faces[face_index] = tuple(exact_uv_face)
        roof_image = material.get("roof_image") if material else None
        if roof_image is not None and counterpart_roof is None:
            ax, ay, az = mesh.vertices[face[0]]
            bx, by, bz = mesh.vertices[face[1]]
            cx, cy, cz = mesh.vertices[face[2]]
            ux, uy, uz = bx-ax, by-ay, bz-az
            vx, vy, vz = cx-ax, cy-ay, cz-az
            nx, ny, nz = uy*vz-uz*vy, uz*vx-ux*vz, ux*vy-uy*vx
            normal_length = math.sqrt(nx*nx + ny*ny + nz*nz) or 1.0
            if abs(nz) / normal_length >= 0.9:
                image = roof_image
                roof_uv_bounds = material.get("roof_uv_bounds") if material else None
                if roof_uv_bounds is not None:
                    min_x = min(vertex[0] for vertex in mesh.vertices)
                    max_x = max(vertex[0] for vertex in mesh.vertices)
                    min_y = min(vertex[1] for vertex in mesh.vertices)
                    max_y = max(vertex[1] for vertex in mesh.vertices)
                    span_x = max(max_x - min_x, 1e-6)
                    span_y = max(max_y - min_y, 1e-6)
                    min_u, max_u, min_v, max_v = roof_uv_bounds
                    projected_face = []
                    for vertex_index in face:
                        x, y, _z = mesh.vertices[vertex_index]
                        projected_face.append(len(output_uvs))
                        output_uvs.append((
                            min_u + (x - min_x) / span_x * (max_u - min_u),
                            max_v - (y - min_y) / span_y * (max_v - min_v),
                        ))
                    output_uv_faces[face_index] = tuple(projected_face)
        environment_image = material.get("environment_image") if material else None
        two_sided = bool(material and material.get("two_sided"))
        black_key = bool(material and material.get("black_key"))
        texture_alpha = bool(material and material.get("texture_alpha"))
        alpha_test = bool(material and material.get("alpha_test"))
        color_key = bool(material and material.get("color_key"))
        vertex_alpha = bool(material and material.get("vertex_alpha"))
        opacity = float(material.get("opacity", 1.0)) if material else 1.0
        decoded_color = mesh.face_colors[face_index] if mesh.face_colors else None
        if vertex_alpha and decoded_color is not None and len(decoded_color) > 3:
            opacity *= min(1.0, decoded_color[3] / 127.0)
        uv_transform = material.get("uv_transform") if material else None
        if environment_image is not None:
            source = environment_image.convert("RGBA")
            width, height = source.size
            tiled = Image.new("RGBA", (width * 3, height * 3))
            for tile_y in range(3):
                for tile_x in range(3):
                    tiled.paste(source, (tile_x * width, tile_y * height))
            env_uv_face = []
            env_samples = []
            for vertex_index in face:
                nx, ny, nz = vertex_normals[vertex_index]
                length = math.sqrt(nx*nx + ny*ny + nz*nz) or 1.0
                nx, ny, nz = nx/length, ny/length, nz/length
                env_u = (math.atan2(ny, nx) / (2.0 * math.pi) + 0.5) % 1.0
                env_v = math.acos(max(-1.0, min(1.0, nz))) / math.pi
                env_uv_face.append(len(output_uvs))
                output_uvs.append((env_u, env_v))
                env_samples.append(source.getpixel((
                    min(width - 1, int(env_u * width)),
                    min(height - 1, int(env_v * height)),
                ))[:3])
            output_uv_faces[face_index] = tuple(env_uv_face)
            colors.append(tuple(sum(sample[axis] for sample in env_samples) // 3 for axis in range(3)))
            face_textures.append((tiled, width, height))
            face_two_sided.append(two_sided)
            face_opacity.append(opacity)
            continue
        if image is None:
            material_name = str(material.get("name", "")).lower() if material else ""
            native_color = material.get("color") if material else None
            decoded_color = mesh.face_colors[face_index] if mesh.face_colors else None
            if any(token in material_name for token in ("black", "zwrite", "shadow")):
                solid_color = (20, 22, 24)
            elif decoded_color is not None:
                solid_color = tuple(decoded_color[:3])
            elif native_color is not None:
                solid_color = tuple(native_color)
            elif any(token in material_name for token in ("exhaust", "glow", "light", "rayorigin")):
                solid_color = (185, 205, 220)
            elif material:
                solid_color = (132, 138, 142)
            else:
                solid_color = (118, 124, 128)
            colors.append(solid_color)
            face_textures.append(None)
            face_two_sided.append(two_sided)
            face_opacity.append(opacity)
            continue
        cache_key = (id(image), black_key, texture_alpha, alpha_test, color_key, uv_transform)
        if cache_key not in texture_cache:
            cached = _TEXTURE_INFO_CACHE.get(cache_key)
            if cached is None or cached[0] is not image:
                if len(_TEXTURE_INFO_CACHE) >= 64:
                    _TEXTURE_INFO_CACHE.clear()
                source = image.convert("RGBA")
                if color_key:
                    key_r, key_g, key_b, _key_a = source.getpixel((0, 0))
                    source.putdata([
                        (r, g, b, 0 if max(abs(r-key_r), abs(g-key_g), abs(b-key_b)) <= 12 else a)
                        for r, g, b, a in source.getdata()
                    ])
                if not texture_alpha:
                    source.putalpha(255)
                elif alpha_test:
                    source.putalpha(source.getchannel("A").point(lambda value: 255 if value >= 128 else 0))
                if black_key:
                    source.putdata([
                        (r, g, b, 0 if r <= 12 and g <= 12 and b <= 12 else a)
                        for r, g, b, a in source.getdata()
                    ])
                if uv_transform is not None:
                    offset_u, offset_v, region_width, region_height = uv_transform
                    source_width, source_height = source.size
                    left = max(0, min(source_width - 1, round(offset_u * source_width)))
                    top = max(0, min(source_height - 1, round(offset_v * source_height)))
                    right = max(left + 1, min(source_width, round((offset_u + region_width) * source_width)))
                    bottom = max(top + 1, min(source_height, round((offset_v + region_height) * source_height)))
                    source = source.crop((left, top, right, bottom))
                width, height = source.size
                tiled = Image.new("RGBA", (width * 3, height * 3))
                for tile_y in range(3):
                    for tile_x in range(3):
                        tiled.paste(source, (tile_x * width, tile_y * height))
                cached = (image, tiled, width, height, source)
                _TEXTURE_INFO_CACHE[cache_key] = cached
            _source_image, tiled, width, height, source = cached
            texture_cache[cache_key] = (tiled, width, height, source.load())
        tiled, width, height, pixels = texture_cache[cache_key]
        uv_face = mesh.uv_faces[face_index] if mesh.uv_faces else face
        if any(index >= len(mesh.uvs) for index in uv_face):
            colors.append(tuple(material.get("color") or (118, 124, 128)) if material else (118, 124, 128))
            face_textures.append(None)
            face_two_sided.append(two_sided)
            face_opacity.append(opacity)
            continue
        sampled_uvs = [mesh.uvs[index] for index in uv_face]
        if uv_transform is not None:
            _offset_u, _offset_v, region_width, region_height = uv_transform
            sampled_uvs = [
                (u / region_width, v / region_height)
                for u, v in sampled_uvs
            ]
            transformed_face = []
            for transformed_uv in sampled_uvs:
                transformed_face.append(len(output_uvs))
                output_uvs.append(transformed_uv)
            output_uv_faces[face_index] = tuple(transformed_face)
        u = sum(value[0] for value in sampled_uvs) / 3.0
        v = sum(value[1] for value in sampled_uvs) / 3.0
        colors.append(tuple(
            pixels[int((u % 1.0) * max(1, width - 1)), int((v % 1.0) * max(1, height - 1))][:3]
        ))
        face_textures.append((tiled, width, height))
        face_two_sided.append(two_sided)
        face_opacity.append(opacity)
    return Mesh(
        mesh.vertices, mesh.faces, mesh.decoder, output_uvs, colors, face_textures,
        output_uv_faces, mesh.face_materials, face_two_sided, face_opacity,
        list(mesh.lines) if mesh.lines else None,
    )


class ModernGLMeshRenderer:
    VERTEX_SHADER = """
        #version 330
        in vec3 in_position;
        in vec2 in_uv;
        uniform vec3 center;
        uniform float radius;
        uniform float yaw;
        uniform float pitch;
        uniform float zoom;
        uniform float aspect_x;
        uniform float aspect_y;
        out vec2 uv;
        void main() {
            vec3 p = in_position - center;
            float sy = sin(yaw), cy = cos(yaw);
            float sp = sin(pitch), cp = cos(pitch);
            float horizontal = p.x * cy + p.y * sy;
            float depth0 = -p.x * sy + p.y * cy;
            float vertical = p.z * cp - depth0 * sp;
            float depth = p.z * sp + depth0 * cp;
            gl_Position = vec4(horizontal / radius * aspect_x * zoom,
                               vertical / radius * aspect_y * zoom,
                               -depth / radius * 0.95, 1.0);
            uv = in_uv;
        }
    """
    FRAGMENT_SHADER = """
        #version 330
        uniform sampler2D texture0;
        uniform bool use_texture;
        uniform vec3 solid_color;
        uniform float opacity;
        in vec2 uv;
        out vec4 frag_color;
        void main() {
            vec4 source = use_texture ? texture(texture0, uv) : vec4(solid_color, 1.0);
            float alpha = source.a * opacity;
            if (alpha <= 0.01) discard;
            frag_color = vec4(source.rgb, alpha);
        }
    """

    def __init__(self):
        if moderngl is None or np is None:
            raise RuntimeError("ModernGL is unavailable")
        self.context = moderngl.create_standalone_context(require=330)
        self.program = self.context.program(
            vertex_shader=self.VERTEX_SHADER,
            fragment_shader=self.FRAGMENT_SHADER,
        )
        self.framebuffer = None
        self.color_buffer = None
        self.depth_buffer = None
        self.size = (0, 0)
        self.mesh_key = None
        self.draw_groups = []
        self.line_group = None

    def _ensure_framebuffer(self, width, height):
        if self.size == (width, height):
            return
        for item in (self.framebuffer, self.color_buffer, self.depth_buffer):
            if item is not None:
                item.release()
        self.color_buffer = self.context.texture((width, height), 4)
        self.depth_buffer = self.context.depth_renderbuffer((width, height))
        self.framebuffer = self.context.framebuffer(self.color_buffer, self.depth_buffer)
        self.size = (width, height)

    def _release_groups(self):
        released_textures = set()
        for vao, buffer, texture, _two_sided, _opacity, _solid_color in self.draw_groups:
            vao.release()
            buffer.release()
            if texture is not None and id(texture) not in released_textures:
                texture.release()
                released_textures.add(id(texture))
        self.draw_groups = []
        if self.line_group is not None:
            vao, buffer = self.line_group
            vao.release()
            buffer.release()
            self.line_group = None

    def _upload_mesh(self, mesh):
        key = (id(mesh), len(mesh.vertices), len(mesh.faces), len(mesh.lines or []), bool(mesh.face_textures))
        if key == self.mesh_key:
            return
        self._release_groups()
        groups = []
        for face_index, face in enumerate(mesh.faces):
            texture_info = mesh.face_textures[face_index] if mesh.face_textures else None
            texture_key = id(texture_info[0]) if texture_info else None
            two_sided = bool(mesh.face_two_sided and mesh.face_two_sided[face_index])
            opacity = mesh.face_opacity[face_index] if mesh.face_opacity else 1.0
            face_color = mesh.face_colors[face_index] if mesh.face_colors else (118, 124, 128)
            solid_color = tuple(float(value) / 255.0 for value in face_color[:3])
            group_key = (texture_key, two_sided, opacity, solid_color)
            if not groups or groups[-1][0] != group_key:
                groups.append((group_key, {
                    "texture": texture_info, "two_sided": two_sided,
                    "opacity": opacity, "solid_color": solid_color, "values": [],
                }))
            group = groups[-1][1]
            uv_face = mesh.uv_faces[face_index] if mesh.uv_faces else face
            for position_index, uv_index in zip(face, uv_face):
                position = mesh.vertices[position_index]
                uv = mesh.uvs[uv_index] if mesh.uvs and uv_index < len(mesh.uvs) else (0.0, 0.0)
                group["values"].append((*position, *uv))
        gpu_textures = {}
        for _group_key, group in groups:
            values = np.asarray(group["values"], dtype="f4")
            buffer = self.context.buffer(values.tobytes())
            vao = self.context.vertex_array(
                self.program,
                [(buffer, "3f 2f", "in_position", "in_uv")],
            )
            texture = None
            texture_info = group["texture"]
            if texture_info:
                tiled, texture_width, texture_height = texture_info
                texture = gpu_textures.get(id(tiled))
                if texture is None:
                    source = tiled.crop((texture_width, texture_height, texture_width * 2, texture_height * 2)).convert("RGBA")
                    texture = self.context.texture(source.size, 4, source.tobytes())
                    texture.filter = (moderngl.LINEAR_MIPMAP_LINEAR, moderngl.LINEAR)
                    texture.repeat_x = True
                    texture.repeat_y = True
                    texture.build_mipmaps()
                    gpu_textures[id(tiled)] = texture
            self.draw_groups.append((
                vao, buffer, texture, group["two_sided"], group["opacity"], group["solid_color"]
            ))
        if mesh.lines:
            line_values = []
            for start, end in mesh.lines:
                line_values.extend((*mesh.vertices[start], 0.0, 0.0))
                line_values.extend((*mesh.vertices[end], 0.0, 0.0))
            line_buffer = self.context.buffer(np.asarray(line_values, dtype="f4").tobytes())
            line_vao = self.context.vertex_array(
                self.program,
                [(line_buffer, "3f 2f", "in_position", "in_uv")],
            )
            self.line_group = (line_vao, line_buffer)
        self.mesh_key = key

    def render(self, mesh, width, height, yaw, pitch, zoom, background):
        self._ensure_framebuffer(width, height)
        self._upload_mesh(mesh)
        vertices = mesh.vertices
        center = tuple(sum(axis) / len(vertices) for axis in zip(*vertices))
        radius = max(math.dist(vertex, center) for vertex in vertices) or 1.0
        minimum = min(width, height)
        self.program["center"].value = center
        self.program["radius"].value = radius
        self.program["yaw"].value = yaw
        self.program["pitch"].value = pitch
        self.program["zoom"].value = zoom
        self.program["aspect_x"].value = 0.84 * minimum / width
        self.program["aspect_y"].value = 0.84 * minimum / height
        red, green, blue = (int(background[index:index+2], 16) / 255.0 for index in (1, 3, 5))
        self.framebuffer.use()
        self.context.enable(moderngl.DEPTH_TEST)
        self.context.depth_func = "<="
        self.context.disable(moderngl.CULL_FACE)
        self.context.enable(moderngl.BLEND)
        self.context.blend_func = moderngl.SRC_ALPHA, moderngl.ONE_MINUS_SRC_ALPHA
        self.framebuffer.clear(red, green, blue, 1.0, depth=1.0)
        ordered_groups = sorted(self.draw_groups, key=lambda group: group[4] < 0.999)
        for vao, _buffer, texture, _material_two_sided, opacity, solid_color in ordered_groups:
            if opacity <= 0.0:
                continue
            self.context.depth_mask = opacity >= 0.999
            self.program["opacity"].value = opacity
            self.program["use_texture"].value = texture is not None
            self.program["solid_color"].value = solid_color
            if texture is not None:
                texture.use(0)
                self.program["texture0"].value = 0
            vao.render(moderngl.TRIANGLES)
        if self.line_group is not None:
            self.context.depth_mask = True
            self.program["opacity"].value = 1.0
            self.program["use_texture"].value = False
            self.program["solid_color"].value = (0.72, 0.70, 0.66)
            self.context.line_width = 1.5
            self.line_group[0].render(moderngl.LINES)
        self.context.depth_mask = True
        raw = self.framebuffer.read(components=3, alignment=1)
        return Image.frombytes("RGB", (width, height), raw).transpose(Image.Transpose.FLIP_TOP_BOTTOM)

    def release(self):
        self._release_groups()
        for item in (self.framebuffer, self.color_buffer, self.depth_buffer, self.program, self.context):
            try:
                if item is not None:
                    item.release()
            except Exception:
                pass


class StaticMeshViewer:
    def __init__(self, parent, mesh: Mesh, title: str, palette=None, icon_callback=None, theme_callback=None):
        self.mesh = mesh
        self.yaw = -0.65
        self.pitch = 0.35
        self.zoom = 1.0
        self.drag = None
        self._draw_after_id = None
        self._interactive_draw_pending = False
        self._centered_vertices = None
        self._model_radius = None
        self._mesh_image_item = None
        self._mesh_photo = None
        self._gpu_renderer = None
        self._gpu_failed = False
        self._gpu_error = ""
        self.palette = palette or {}
        self.window = tk.Toplevel(parent)
        self.window.title(f"Static Mesh Preview - {title}")
        self.window.geometry("900x680")
        self.window.minsize(520, 400)
        if icon_callback:
            icon_callback(self.window)
        if theme_callback:
            theme_callback(self.window)
        background = self.palette.get("text_bg", "#101827")
        foreground = self.palette.get("text_fg", "#e5e7eb")
        self.canvas = tk.Canvas(self.window, background=background, highlightthickness=0)
        self.canvas.pack(fill=tk.BOTH, expand=True)
        self.canvas.bind("<Configure>", self.draw)
        self.canvas.bind("<ButtonPress-1>", self._press)
        self.canvas.bind("<B1-Motion>", self._drag)
        self.canvas.bind("<ButtonRelease-1>", self._release)
        self.canvas.bind("<MouseWheel>", self._wheel)
        self.canvas.bind("<Button-4>", lambda _event: self._zoom(1.12))
        self.canvas.bind("<Button-5>", lambda _event: self._zoom(1 / 1.12))
        self.canvas.bind("<Double-Button-1>", self._reset)
        self.canvas.create_text(12, 12, anchor="nw", fill=foreground, tags="status")
        self.window.transient(parent)
        self.window.update_idletasks()
        x = parent.winfo_rootx() + max(0, (parent.winfo_width() - self.window.winfo_width()) // 2)
        y = parent.winfo_rooty() + max(0, (parent.winfo_height() - self.window.winfo_height()) // 2)
        self.window.geometry(f"+{x}+{y}")
        self.window.after_idle(self.draw)

    def _press(self, event):
        self.drag = (event.x, event.y, self.yaw, self.pitch)

    def _drag(self, event):
        if not self.drag:
            return
        x, y, yaw, pitch = self.drag
        self.yaw = (yaw + (event.x - x) * 0.012) % math.tau
        self.pitch = (pitch + (event.y - y) * 0.012) % math.tau
        self._request_interactive_draw()

    def _release(self, _event=None):
        self.drag = None
        if self._draw_after_id is not None:
            try:
                self.canvas.after_cancel(self._draw_after_id)
            except Exception:
                pass
            self._draw_after_id = None
        self._interactive_draw_pending = False
        self.draw()

    def _request_interactive_draw(self):
        self._interactive_draw_pending = True
        if self._draw_after_id is None:
            self._draw_after_id = self.canvas.after(33, self._run_interactive_draw)

    def _run_interactive_draw(self):
        self._draw_after_id = None
        if not self._interactive_draw_pending:
            return
        self._interactive_draw_pending = False
        self.draw(interactive=True)

    def _wheel(self, event):
        self._zoom(1.12 if event.delta > 0 else 1 / 1.12)

    def _zoom(self, amount):
        self.zoom = max(0.15, min(12.0, self.zoom * amount))
        self.draw()

    def _reset(self, _event=None):
        self.yaw, self.pitch, self.zoom = -0.65, 0.35, 1.0
        self.draw()

    def _paint_textured_triangle(self, frame, screen_points, face, face_index, shade):
        if not self.mesh.uvs or not self.mesh.face_textures or face_index >= len(self.mesh.face_textures):
            return False
        texture_info = self.mesh.face_textures[face_index]
        if not texture_info:
            return False
        texture, texture_width, texture_height = texture_info
        destination = [screen_points[index][:2] for index in face]
        xs = [point[0] for point in destination]
        ys = [point[1] for point in destination]
        left = max(0, int(math.floor(min(xs))))
        top = max(0, int(math.floor(min(ys))))
        right = min(frame.width, int(math.ceil(max(xs))) + 1)
        bottom = min(frame.height, int(math.ceil(max(ys))) + 1)
        if right <= left or bottom <= top:
            return False

        raw_uvs = [self.mesh.uvs[index] for index in face]
        base_u, base_v = raw_uvs[0]
        adjusted = []
        for u, v in raw_uvs:
            u += round(base_u - u)
            v += round(base_v - v)
            adjusted.append(((u + 1.0) * texture_width, (v + 1.0) * texture_height))

        (x0, y0), (x1, y1), (x2, y2) = destination
        determinant = x0 * (y1-y2) + x1 * (y2-y0) + x2 * (y0-y1)
        if abs(determinant) < 1.0e-6:
            return False

        def coefficients(values):
            value0, value1, value2 = values
            a = (value0*(y1-y2) + value1*(y2-y0) + value2*(y0-y1)) / determinant
            b = (value0*(x2-x1) + value1*(x0-x2) + value2*(x1-x0)) / determinant
            c = (value0*(x1*y2-x2*y1) + value1*(x2*y0-x0*y2) + value2*(x0*y1-x1*y0)) / determinant
            return a, b, c + a*left + b*top

        a, b, c = coefficients([uv[0] for uv in adjusted])
        d, e, f = coefficients([uv[1] for uv in adjusted])
        patch = texture.transform(
            (right-left, bottom-top),
            Image.Transform.AFFINE,
            (a, b, c, d, e, f),
            resample=Image.Resampling.BILINEAR,
        )
        if shade < 0.995:
            lookup = [min(255, int(value * shade)) for value in range(256)]
            patch = patch.point(lookup * 3)
        mask = Image.new("L", patch.size, 0)
        mask_draw = ImageDraw.Draw(mask)
        mask_draw.polygon([(x-left, y-top) for x, y in destination], fill=255)
        frame.paste(patch, (left, top), mask)
        return True

    def _render_zbuffer(self, width, height, points, polygons, background):
        if np is None:
            return None
        background_rgb = tuple(int(background[index:index+2], 16) for index in (1, 3, 5))
        pixels = np.empty((height, width, 3), dtype=np.uint8)
        pixels[:, :] = background_rgb
        depth_buffer = np.full((height, width), -np.inf, dtype=np.float32)
        texture_cache = getattr(self, "_texture_array_cache", None)
        if texture_cache is None:
            texture_cache = self._texture_array_cache = {}

        for _depth, face_index, face, color, _shade in polygons:
            triangle = [points[index] for index in face]
            xs = [point[0] for point in triangle]
            ys = [point[1] for point in triangle]
            left = max(0, int(math.floor(min(xs))))
            top = max(0, int(math.floor(min(ys))))
            right = min(width, int(math.ceil(max(xs))) + 1)
            bottom = min(height, int(math.ceil(max(ys))) + 1)
            if right <= left or bottom <= top:
                continue
            x0, y0, z0 = triangle[0]
            x1, y1, z1 = triangle[1]
            x2, y2, z2 = triangle[2]
            denominator = (y1-y2)*(x0-x2) + (x2-x1)*(y0-y2)
            if abs(denominator) < 1.0e-7:
                continue
            grid_y, grid_x = np.mgrid[top:bottom, left:right]
            sample_x = grid_x + 0.5
            sample_y = grid_y + 0.5
            weight0 = ((y1-y2)*(sample_x-x2) + (x2-x1)*(sample_y-y2)) / denominator
            weight1 = ((y2-y0)*(sample_x-x2) + (x0-x2)*(sample_y-y2)) / denominator
            weight2 = 1.0 - weight0 - weight1
            inside = (weight0 >= -1.0e-5) & (weight1 >= -1.0e-5) & (weight2 >= -1.0e-5)
            depth = weight0*z0 + weight1*z1 + weight2*z2
            depth_view = depth_buffer[top:bottom, left:right]
            visible = inside & (depth > depth_view)
            if not visible.any():
                continue

            texture_info = None
            if self.mesh.face_textures and face_index < len(self.mesh.face_textures):
                texture_info = self.mesh.face_textures[face_index]
            if texture_info and self.mesh.uvs:
                texture, texture_width, texture_height = texture_info
                key = id(texture)
                texture_pixels = texture_cache.get(key)
                if texture_pixels is None:
                    texture_pixels = np.asarray(texture, dtype=np.uint8)
                    texture_cache[key] = texture_pixels
                uv_face = self.mesh.uv_faces[face_index] if self.mesh.uv_faces else face
                raw_uvs = [self.mesh.uvs[index] for index in uv_face]
                base_u, base_v = raw_uvs[0]
                adjusted = []
                for u, v in raw_uvs:
                    adjusted.append((u + round(base_u-u) + 1.0, v + round(base_v-v) + 1.0))
                texture_x = (weight0*adjusted[0][0] + weight1*adjusted[1][0] + weight2*adjusted[2][0]) * texture_width
                texture_y = (weight0*adjusted[0][1] + weight1*adjusted[1][1] + weight2*adjusted[2][1]) * texture_height
                texture_x = np.clip(texture_x, 0.0, texture_pixels.shape[1]-1.001)
                texture_y = np.clip(texture_y, 0.0, texture_pixels.shape[0]-1.001)
                x_low = texture_x.astype(np.int32)
                y_low = texture_y.astype(np.int32)
                x_high = np.minimum(x_low + 1, texture_pixels.shape[1]-1)
                y_high = np.minimum(y_low + 1, texture_pixels.shape[0]-1)
                x_fraction = (texture_x - x_low)[..., None]
                y_fraction = (texture_y - y_low)[..., None]
                top_sample = texture_pixels[y_low, x_low] * (1.0-x_fraction) + texture_pixels[y_low, x_high] * x_fraction
                bottom_sample = texture_pixels[y_high, x_low] * (1.0-x_fraction) + texture_pixels[y_high, x_high] * x_fraction
                sampled = (top_sample * (1.0-y_fraction) + bottom_sample * y_fraction).astype(np.uint8)
                if sampled.shape[2] >= 4:
                    alpha = sampled[..., 3].astype(np.float32) / 255.0
                    if self.mesh.face_opacity and face_index < len(self.mesh.face_opacity):
                        alpha *= self.mesh.face_opacity[face_index]
                    visible &= alpha > 0.01
                source = sampled[..., :3]
            else:
                rgb = tuple(int(color[index:index+2], 16) for index in (1, 3, 5))
                source = np.empty((bottom-top, right-left, 3), dtype=np.uint8)
                source[:, :] = rgb
            view = pixels[top:bottom, left:right]
            view[visible] = source[visible]
            depth_view[visible] = depth[visible]
        return Image.fromarray(pixels, "RGB")

    def draw(self, _event=None, interactive=False):
        width = max(1, self.canvas.winfo_width())
        height = max(1, self.canvas.winfo_height())
        if Image is not None and ImageTk is not None and moderngl is not None and not self._gpu_failed:
            try:
                if self._gpu_renderer is None:
                    self._gpu_renderer = ModernGLMeshRenderer()
                background = self.palette.get("text_bg", "#101827")
                frame = self._gpu_renderer.render(
                    self.mesh,
                    width,
                    height,
                    self.yaw,
                    self.pitch,
                    self.zoom,
                    background,
                )
                self._mesh_photo = ImageTk.PhotoImage(frame, master=self.canvas)
                if self._mesh_image_item is None:
                    self._mesh_image_item = self.canvas.create_image(
                        0, 0, anchor="nw", image=self._mesh_photo, tags="mesh"
                    )
                else:
                    self.canvas.itemconfigure(self._mesh_image_item, image=self._mesh_photo)
                self.canvas.tag_raise("status")
                self.canvas.itemconfigure(
                    "status",
                    text=f"{len(self.mesh.vertices):,} vertices   {len(self.mesh.faces):,} triangles   {self.mesh.decoder}   GPU\nDrag to rotate   Wheel to zoom   Double-click to reset",
                )
                return
            except Exception as exc:
                self._gpu_failed = True
                self._gpu_error = f"{type(exc).__name__}: {exc}"
                if self._gpu_renderer is not None:
                    self._gpu_renderer.release()
                    self._gpu_renderer = None
        if Image is None or ImageDraw is None or ImageTk is None:
            self.canvas.delete("mesh")
        if self._centered_vertices is None:
            cx = sum(v[0] for v in self.mesh.vertices) / len(self.mesh.vertices)
            cy = sum(v[1] for v in self.mesh.vertices) / len(self.mesh.vertices)
            cz = sum(v[2] for v in self.mesh.vertices) / len(self.mesh.vertices)
            self._centered_vertices = [(x - cx, y - cy, z - cz) for x, y, z in self.mesh.vertices]
            self._model_radius = max(
                math.sqrt(x*x + y*y + z*z) for x, y, z in self._centered_vertices
            ) or 1.0
        centered = self._centered_vertices
        radius = self._model_radius
        sy, cyaw = math.sin(self.yaw), math.cos(self.yaw)
        sp, cp = math.sin(self.pitch), math.cos(self.pitch)
        rotated = []
        for x, y, z in centered:
            horizontal = x * cyaw + y * sy
            depth = -x * sy + y * cyaw
            vertical = z * cp - depth * sp
            depth = z * sp + depth * cp
            rotated.append((horizontal, vertical, depth))
        scale = min(width, height) * 0.42 * self.zoom / radius
        points = [(width * 0.5 + x * scale, height * 0.5 - y * scale, z) for x, y, z in rotated]
        light = (0.25, -0.45, 0.86)
        polygons = []
        for face_index, face in enumerate(self.mesh.faces):
            a, b, c = (rotated[i] for i in face)
            ux, uy, uz = b[0]-a[0], b[1]-a[1], b[2]-a[2]
            vx, vy, vz = c[0]-a[0], c[1]-a[1], c[2]-a[2]
            nx, ny, nz = uy*vz-uz*vy, uz*vx-ux*vz, ux*vy-uy*vx
            length = math.sqrt(nx*nx + ny*ny + nz*nz) or 1.0
            textured = bool(self.mesh.face_colors)
            ambient = 0.55 if textured else 0.35
            shade = max(ambient, min(1.0, ambient + (1.0 - ambient) * abs((nx*light[0]+ny*light[1]+nz*light[2]) / length)))
            if textured:
                shade = 1.0
            if self.mesh.face_colors and face_index < len(self.mesh.face_colors):
                red, green, blue = self.mesh.face_colors[face_index]
                color = "#{0:02x}{1:02x}{2:02x}".format(int(red*shade), int(green*shade), int(blue*shade))
            else:
                color = "#{0:02x}{1:02x}{2:02x}".format(int(58*shade), int(166*shade), int(210*shade))
            polygons.append((sum(points[i][2] for i in face) / 3.0, face_index, face, color, shade))
        if Image is not None and ImageDraw is not None and ImageTk is not None:
            background = self.palette.get("text_bg", "#101827")
            frame = self._render_zbuffer(width, height, points, polygons, background)
            if frame is None:
                frame = Image.new("RGB", (width, height), background)
                painter = ImageDraw.Draw(frame)
                for _depth, face_index, face, color, shade in sorted(polygons):
                    coords = [points[index][:2] for index in face]
                    if not self._paint_textured_triangle(frame, points, face, face_index, shade):
                        painter.polygon(coords, fill=color, outline=None if self.mesh.face_colors else "#172033")
            self._mesh_photo = ImageTk.PhotoImage(frame, master=self.canvas)
            if self._mesh_image_item is None:
                self._mesh_image_item = self.canvas.create_image(
                    0, 0, anchor="nw", image=self._mesh_photo, tags="mesh"
                )
            else:
                self.canvas.itemconfigure(self._mesh_image_item, image=self._mesh_photo)
        else:
            for _depth, _face_index, face, color, _shade in sorted(polygons):
                coords = [coordinate for index in face for coordinate in points[index][:2]]
                self.canvas.create_polygon(
                    *coords,
                    fill=color,
                    outline=color if self.mesh.face_colors else "#172033",
                    width=1,
                    tags="mesh",
                )
        self.canvas.tag_raise("status")
        fallback = f"   Software ({self._gpu_error})" if self._gpu_error else ""
        self.canvas.itemconfigure("status", text=f"{len(self.mesh.vertices):,} vertices   {len(self.mesh.faces):,} triangles   {self.mesh.decoder}{fallback}\nDrag to rotate   Wheel to zoom   Double-click to reset")


def open_viewer(parent, main_data: bytes, resource_data: bytes, big_endian: bool, title: str, **kwargs):
    mesh = decode_static_mesh(main_data, resource_data, big_endian)
    return StaticMeshViewer(parent, mesh, title, **kwargs)


class EmbeddedStaticMeshViewer(StaticMeshViewer):
    def __init__(self, text_widget, mesh: Mesh, palette=None, height=None, connected_mesh=None, textured_mesh=None, textured_connected_mesh=None):
        self.single_mesh = mesh
        self.connected_mesh = connected_mesh
        self.textured_mesh = textured_mesh
        self.textured_connected_mesh = textured_connected_mesh
        self.mesh = textured_connected_mesh or textured_mesh or connected_mesh or mesh
        self.yaw = -0.65
        self.pitch = 0.35
        self.zoom = 1.0
        self.drag = None
        self._draw_after_id = None
        self._interactive_draw_pending = False
        self._centered_vertices = None
        self._model_radius = None
        self._mesh_image_item = None
        self._mesh_photo = None
        self._gpu_renderer = None
        self._gpu_failed = False
        self._gpu_error = ""
        self.palette = palette or {}
        self.window = None
        background = self.palette.get("text_bg", "#101827")
        foreground = self.palette.get("text_fg", "#e5e7eb")
        width = max(240, text_widget.winfo_width() - 16)
        if height is None:
            height = max(300, text_widget.winfo_height() - 48)
        self.container = ttk.Frame(text_widget)
        self.canvas = tk.Canvas(
            self.container,
            width=width,
            height=height,
            background=background,
            highlightthickness=0,
        )
        self.canvas.bind("<Configure>", self.draw)
        self.canvas.bind("<ButtonPress-1>", self._press)
        self.canvas.bind("<B1-Motion>", self._drag)
        self.canvas.bind("<ButtonRelease-1>", self._release)
        self.canvas.bind("<MouseWheel>", self._wheel)
        self.canvas.bind("<Button-4>", lambda _event: self._zoom(1.12))
        self.canvas.bind("<Button-5>", lambda _event: self._zoom(1 / 1.12))
        self.canvas.bind("<Double-Button-1>", self._reset)
        self.canvas.create_text(12, 12, anchor="nw", fill=foreground, tags="status")
        self.canvas.pack(fill=tk.BOTH, expand=True)
        self._text_widget = text_widget
        self._resize_binding = text_widget.bind("<Configure>", self._resize_to_text, add="+")
        text_widget.window_create(tk.END, window=self.container)
        text_widget.insert(tk.END, "\n")
        self.canvas.after_idle(self.draw)

    def _resize_to_text(self, _event=None):
        if self.canvas.winfo_exists():
            self.canvas.configure(
                width=max(240, self._text_widget.winfo_width() - 16),
                height=max(300, self._text_widget.winfo_height() - 48),
            )

    def destroy(self):
        if self._draw_after_id is not None:
            try:
                self.canvas.after_cancel(self._draw_after_id)
            except Exception:
                pass
            self._draw_after_id = None
        if self._gpu_renderer is not None:
            self._gpu_renderer.release()
            self._gpu_renderer = None
        try:
            if self._resize_binding:
                self._text_widget.unbind("<Configure>", self._resize_binding)
        except Exception:
            pass
        try:
            self.container.destroy()
        except Exception:
            pass


def embed_viewer(text_widget, main_data: bytes, resource_data: bytes, big_endian: bool, **kwargs):
    texture = kwargs.get("texture")
    gx_variant = kwargs.get("gx_variant")
    mesh = decode_static_mesh(main_data, resource_data, big_endian, texture, gx_variant)
    textured_mesh = texture_mesh(mesh, texture)
    if textured_mesh is mesh:
        textured_mesh = None
    connected_mesh = None
    textured_connected_mesh = None
    connected_parts = kwargs.get("connected_parts") or []
    if connected_parts:
        decoded = [transform_mesh(mesh, kwargs.get("mesh_transform"))]
        textured_decoded = [transform_mesh(texture_mesh(mesh, kwargs.get("texture")), kwargs.get("mesh_transform"))]
        for part in connected_parts:
            part_main, part_resource = part[:2]
            part_transform = part[2] if len(part) > 2 else None
            part_texture = part[3] if len(part) > 3 else None
            try:
                part_mesh = decode_static_mesh(part_main, part_resource, big_endian, part_texture, gx_variant)
            except MeshDecodeError:
                continue
            decoded.append(transform_mesh(part_mesh, part_transform))
            textured_decoded.append(transform_mesh(texture_mesh(part_mesh, part_texture), part_transform))
        connected_mesh = combine_meshes(decoded)
        if all(item.face_colors is not None for item in textured_decoded):
            textured_connected_mesh = combine_meshes(textured_decoded)
    return EmbeddedStaticMeshViewer(
        text_widget,
        mesh,
        palette=kwargs.get("palette"),
        connected_mesh=connected_mesh,
        textured_mesh=textured_mesh,
        textured_connected_mesh=textured_connected_mesh,
    )
