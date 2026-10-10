"""PS2-specific Pipeworks type-0 static-mesh decoding and ownership helpers."""

from __future__ import annotations

import math
import struct
from pathlib import Path


_FORMATS = {0x02, 0x12, 0x42, 0x102, 0x112, 0x116, 0x118, 0x142, 0x149, 0x152, 0x242, 0x252}


def _u32(data, offset):
    return struct.unpack_from("<I", data, offset)[0]


def _layout(main):
    """Return (surface count, record base/stride, material offset, descriptor stride)."""
    ste_count = _u32(main, 0) if len(main) >= 4 else 0
    gu_count = _u32(main, 0x10) if len(main) >= 0x14 else 0
    ste_end = 0x20 + ste_count * 0x50 + 0x1C
    gu_end = 0x20 + gu_count * 0x60 + 0x28
    ste_valid = 0 < ste_count <= 4096 and ste_end + (ste_count - 1) * 0x40 + 0x18 <= len(main)
    gu_valid = 0 < gu_count <= 4096 and gu_end + (gu_count - 1) * 0x48 + 0x20 <= len(main)
    if gu_valid:
        stride = _u32(main, gu_end + 4)
        fmt = _u32(main, gu_end + 8)
        if stride in {0x10, 0x14, 0x18, 0x24, 0x28, 0x2C} and fmt in _FORMATS:
            return gu_count, 0x20, 0x60, 0x16, gu_end, 0x48, 0x1C
    if ste_valid:
        stride = _u32(main, ste_end + 4)
        fmt = _u32(main, ste_end + 8)
        if stride in {0x10, 0x14, 0x18, 0x24, 0x28, 0x2C} and fmt in _FORMATS:
            return ste_count, 0x20, 0x50, 0x0A, ste_end, 0x40, 0x14
    # A few small STE effects omit the usual descriptor-table padding.
    for offset in range(0x20, max(0x20, len(main) - 0x18 + 1), 4):
        count = _u32(main, offset)
        stride = _u32(main, offset + 4)
        fmt = _u32(main, offset + 8)
        relative = _u32(main, offset + 0x10)
        if 2 < count < 100000 and stride in {0x10, 0x14, 0x18, 0x20, 0x24, 0x28, 0x2C} and fmt in _FORMATS and relative >= 0:
            surface_count = ste_count if 0 < ste_count <= 4096 else 1
            return surface_count, 0x20, 0x50, 0x0A, offset, 0x40, 0x14
    return None


def material_ids(main, known_ids=None):
    layout = _layout(main)
    if layout is None:
        return []
    count, base, stride, material_offset, _descriptors, _descriptor_stride, _size_offset = layout
    result = []
    for index in range(count):
        value = struct.unpack_from("<H", main, base + index * stride + material_offset)[0]
        if known_ids is None or value in known_ids:
            result.append(value)
        else:
            result.append(None)
    return result


def texture_asset_ids(material_blob):
    """PS2 materials store primary/secondary texture or IFL string IDs at 0x38."""
    if len(material_blob) < 0x3A:
        return []
    result = []
    for offset in range(0x38, min(len(material_blob) - 1, 0x40), 2):
        value = struct.unpack_from("<H", material_blob, offset)[0]
        if value not in (0, 0xFFFF) and value not in result:
            result.append(value)
    return result


def _word_swapped_f32(data, offset):
    if offset + 4 > len(data):
        return 0.0
    raw = data[offset:offset + 4]
    return struct.unpack("<f", raw[2:4] + raw[0:2])[0]


def texture_transform(material_blob):
    """Return PS2 region-repeat (offset U/V, region width/height), if present."""
    if len(material_blob) < 0x4C:
        return None
    values = tuple(_word_swapped_f32(material_blob, offset) for offset in (0x3C, 0x40, 0x44, 0x48))
    if not all(math.isfinite(value) for value in values):
        return None
    offset_u, offset_v, width, height = values
    if width <= 0.0 or height <= 0.0:
        return None
    if any(abs(value) > 16.0 for value in values):
        return None
    return offset_u, offset_v, width, height


def material_flags(mesh_name, material_blob):
    name = str(mesh_name or "").lower()
    temporary_facade = "_tmp" in name or "/tmp" in name
    return {
        "two_sided": temporary_facade or bool(len(material_blob) > 7 and material_blob[7] & 0x01),
        "black_key": False,
        "legacy_uv": False,
    }


def _strip_faces(indices, markers):
    faces = []
    for index in range(len(indices) - 2):
        if markers is not None and not markers[index + 2]:
            continue
        face = (indices[index], indices[index + 1], indices[index + 2])
        if index & 1:
            face = (face[1], face[0], face[2])
        if len(set(face)) == 3:
            faces.append(face)
    return faces


def _align_16(value):
    return (value + 15) & ~15


def _uv_offset(fmt, count):
    packed_planes = 0
    if fmt in {0x112, 0x116, 0x118, 0x142, 0x149}:
        packed_planes = 1
    elif fmt == 0x152:
        packed_planes = 2
    elif fmt == 0x242:
        packed_planes = 1
    elif fmt == 0x252:
        packed_planes = 2
    return count * 16 + packed_planes * _align_16(count * 4)


def decode(main, resource, mesh_factory, validate_mesh, decode_error):
    layout = _layout(main)
    if layout is None:
        raise decode_error("This PS2 type-0 descriptor layout is not decoded yet.")
    surface_count, _base, _stride, _material_offset, descriptor_base, descriptor_stride, size_offset = layout
    materials = material_ids(main)
    vertices = []
    faces = []
    uvs = []
    uv_faces = []
    face_materials = []
    face_colors = []
    for surface_index in range(surface_count):
        offset = descriptor_base + surface_index * descriptor_stride
        count = _u32(main, offset)
        fmt = _u32(main, offset + 8)
        relative = _u32(main, offset + 0x10)
        region_size = _u32(main, offset + size_offset)
        if not (2 < count < 100000 and fmt in _FORMATS and relative + count * 16 <= len(resource)):
            continue
        region_end = min(len(resource), relative + region_size) if region_size else len(resource)
        packet_vertices = [struct.unpack_from("<3f", resource, relative + index * 16) for index in range(count)]
        if not all(math.isfinite(value) and abs(value) < 1.0e20 for vertex in packet_vertices for value in vertex):
            continue
        controls = [resource[relative + index * 16 + 12:relative + index * 16 + 16] for index in range(count)]
        flags = set(controls)
        markers = (
            [value == b"\0\0\x80?" for value in controls]
            if flags.issubset({b"\0\0\0\0", b"\0\0\x80?"}) else None
        )
        packet_faces = _strip_faces(list(range(count)), markers)
        if not packet_faces:
            continue
        packet_uvs = []
        uv_start = relative + _uv_offset(fmt, count)
        uv_stride = 8 if fmt in {0x242, 0x252} else 4
        if uv_start + count * uv_stride <= region_end:
            packet_uvs = [
                tuple(value / 4096.0 for value in struct.unpack_from("<2h", resource, uv_start + index * uv_stride))
                for index in range(count)
            ]
        packet_colors = None
        if fmt not in {0x12, 0x42, 0x102}:
            color_start = relative + count * 16
            if color_start + count * 4 <= region_end:
                packet_colors = [resource[color_start + index * 4:color_start + index * 4 + 4] for index in range(count)]
        vertex_base = len(vertices)
        uv_base = len(uvs)
        vertices.extend(packet_vertices)
        faces.extend(tuple(vertex_base + value for value in face) for face in packet_faces)
        if packet_uvs:
            uvs.extend(packet_uvs)
            uv_faces.extend(tuple(uv_base + value for value in face) for face in packet_faces)
        else:
            uvs.append((0.0, 0.0))
            uv_faces.extend([(uv_base, uv_base, uv_base)] * len(packet_faces))
        face_materials.extend([materials[surface_index] if surface_index < len(materials) else None] * len(packet_faces))
        if packet_colors is not None:
            face_colors.extend([
                tuple(sum(packet_colors[index][axis] for index in face) // 3 for axis in range(4))
                for face in packet_faces
            ])
        else:
            face_colors.extend([None] * len(packet_faces))
    if not faces:
        raise decode_error("This PS2 type-0 descriptor layout is not decoded yet.")
    return validate_mesh(mesh_factory(
        vertices, faces, "PS2 type-0 attribute streams", uvs, face_colors,
        uv_faces=uv_faces, face_materials=face_materials,
    ))


def connected_entries(parsed_files, selected_entry):
    selected_index = next((
        index for index, item in enumerate(parsed_files)
        if item is selected_entry or (
            not item.get("is_resource") and item.get("file_type") == 0
            and item.get("file_num") == selected_entry.get("file_num")
        )
    ), -1)
    if selected_index < 0:
        return []
    owner_index = next((
        index for index in range(selected_index - 1, -1, -1)
        if not parsed_files[index].get("is_resource") and parsed_files[index].get("file_type") == 16
    ), None)
    if owner_index is None:
        return []
    end = next((
        index for index in range(owner_index + 1, len(parsed_files))
        if not parsed_files[index].get("is_resource") and parsed_files[index].get("file_type") == 16
    ), len(parsed_files))
    return [
        item for item in parsed_files[owner_index + 1:end]
        if not item.get("is_resource") and item.get("file_type") == 0
        and item.get("file_num") != selected_entry.get("file_num")
    ]


def owner_name(parsed_files, entry):
    index = next((
        index for index, item in enumerate(parsed_files)
        if item is entry or (
            not item.get("is_resource") and item.get("file_type") == 0
            and item.get("file_num") == entry.get("file_num")
        )
    ), -1)
    owner = next((
        parsed_files[position] for position in range(index - 1, -1, -1)
        if not parsed_files[position].get("is_resource") and parsed_files[position].get("file_type") == 16
    ), None)
    return Path(str(owner.get("name", "")).replace("\\", "/")).stem if owner else ""


def _multiply(left, right):
    return [
        [sum(left[row][axis] * right[axis][column] for axis in range(4)) for column in range(4)]
        for row in range(4)
    ]


def _matrix(qx, qy, qz, qw, tx, ty, tz):
    norm = qx * qx + qy * qy + qz * qz + qw * qw
    scale = 2.0 / norm if norm > 1.0e-12 else 0.0
    xx, yy, zz = qx * qx * scale, qy * qy * scale, qz * qz * scale
    xy, xz, yz = qx * qy * scale, qx * qz * scale, qy * qz * scale
    wx, wy, wz = qw * qx * scale, qw * qy * scale, qw * qz * scale
    return [
        [1.0 - yy - zz, xy + wz, xz - wy, tx],
        [xy - wz, 1.0 - xx - zz, yz + wx, ty],
        [xz + wy, yz - wx, 1.0 - xx - yy, tz],
        [0.0, 0.0, 0.0, 1.0],
    ]


def _embedded_matrix(qx, qy, qz, qw, tx, ty, tz):
    matrix = _matrix(qx, qy, qz, qw, tx, ty, tz)
    return [
        [matrix[column][row] if column < 3 and row < 3 else matrix[row][column] for column in range(4)]
        for row in range(4)
    ]


def part_transforms(parser, parsed_files, group):
    """Read the PS2 type-3 hierarchy and type-4 default-pose transforms."""
    indices = [
        index for index, item in enumerate(parsed_files)
        if any(item is member or (
            item.get("file_num") == member.get("file_num")
            and not item.get("is_resource") and item.get("file_type") == 0
        ) for member in group)
    ]
    if not indices:
        return {}
    owner_index = next((
        index for index in range(min(indices) - 1, -1, -1)
        if not parsed_files[index].get("is_resource") and parsed_files[index].get("file_type") == 16
    ), None)
    if owner_index is None:
        return {}
    previous_owner = next((
        index for index in range(owner_index - 1, -1, -1)
        if not parsed_files[index].get("is_resource") and parsed_files[index].get("file_type") == 16
    ), -1)
    hierarchy_index = next((
        index for index in range(owner_index - 1, previous_owner, -1)
        if not parsed_files[index].get("is_resource") and parsed_files[index].get("file_type") == 3
    ), None)
    if hierarchy_index is None:
        return {}
    animation = next((
        item for item in parsed_files[hierarchy_index + 1:min(len(parsed_files), hierarchy_index + 5)]
        if not item.get("is_resource") and item.get("file_type") == 4
    ), None)
    skeleton_entry = parsed_files[hierarchy_index]
    skeleton = bytes(parser.read_bytes(skeleton_entry["offset"], skeleton_entry["size"]))
    pose = bytes(parser.read_bytes(animation["offset"], animation["size"])) if animation is not None else b""
    strings = [value.decode("latin1", errors="replace") for value in parser._read_pipeworks_string_entries()]
    if len(skeleton) < 0x30:
        return {}
    node_count = _u32(skeleton, 0x20)
    node_offsets = _u32(skeleton, 0x2C)
    nodes = {}
    animation_count = _u32(pose, 0x2C) if len(pose) >= 0x34 else 0
    animation_offsets = _u32(pose, 0x30) if len(pose) >= 0x34 else 0
    table_pose = (
        0 < node_count <= animation_count < 512
        and node_offsets + node_count * 4 <= len(skeleton)
        and animation_offsets + animation_count * 4 <= len(pose)
    )
    for table_index in range(node_count if table_pose else 0):
        relative = _u32(skeleton, node_offsets + table_index * 4)
        if relative + 0x10 > len(skeleton):
            continue
        node_index, parent, _child_count, name_index = struct.unpack_from("<4i", skeleton, relative)
        if not (0 <= node_index < animation_count and 0 <= name_index < len(strings)):
            continue
        transform_relative = _u32(pose, animation_offsets + node_index * 4)
        if transform_relative + 0x4C > len(pose):
            continue
        tx, ty, tz = struct.unpack_from("<3f", pose, transform_relative + 0x24)
        qx, qy, qz, qw = struct.unpack_from("<4f", pose, transform_relative + 0x3C)
        if not all(math.isfinite(value) for value in (tx, ty, tz, qx, qy, qz, qw)):
            continue
        nodes[node_index] = {
            "parent": parent,
            "name": strings[name_index],
            "local": _matrix(qx, qy, qz, qw, tx, ty, tz),
        }

    if not table_pose:
        visited = set()

        def walk(relative):
            if relative in visited or relative + 0x30 > len(skeleton):
                return
            visited.add(relative)
            node_index, parent, child_count, name_index = struct.unpack_from("<4i", skeleton, relative)
            if not (0 <= node_index < 512 and 0 <= child_count <= 128 and 0 <= name_index < len(strings)):
                return
            qx, qy, qz, qw = struct.unpack_from("<4f", skeleton, relative + 0x10)
            tx, ty, tz = struct.unpack_from("<3f", skeleton, relative + 0x20)
            if all(math.isfinite(value) for value in (tx, ty, tz, qx, qy, qz, qw)):
                nodes[node_index] = {
                    "parent": parent,
                    "name": strings[name_index],
                    "local": _embedded_matrix(qx, qy, qz, qw, tx, ty, tz),
                }
            if relative + 0x30 + child_count * 4 <= len(skeleton):
                for child in struct.unpack_from("<" + "I" * child_count, skeleton, relative + 0x30):
                    walk(child)

        walk(_u32(skeleton, 0x1C))

    globals_by_index = {}

    def global_matrix(index, visiting=None):
        if index in globals_by_index:
            return globals_by_index[index]
        visiting = set() if visiting is None else visiting
        if index in visiting:
            return nodes[index]["local"]
        visiting.add(index)
        node = nodes[index]
        result = node["local"]
        if node["parent"] in nodes and node["parent"] != index:
            result = _multiply(global_matrix(node["parent"], visiting), result)
        visiting.remove(index)
        globals_by_index[index] = result
        return result

    named = {node["name"].lower(): global_matrix(index) for index, node in nodes.items()}
    transforms = {}
    for part in group:
        basename = Path(str(part.get("name", "")).replace("\\", "/")).name.lower()
        matches = [(name, matrix) for name, matrix in named.items() if basename.endswith(name)]
        if matches:
            transforms[part.get("file_num")] = max(matches, key=lambda match: len(match[0]))[1]
    return transforms
