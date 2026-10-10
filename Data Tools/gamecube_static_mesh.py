"""GameCube-specific Pipeworks static-mesh hierarchy and UV policy."""

from __future__ import annotations

import math
import struct
from pathlib import Path


def _multiply(left, right):
    return [
        [sum(left[row][axis] * right[axis][column] for axis in range(4)) for column in range(4)]
        for row in range(4)
    ]


def _matrix(qx, qy, qz, qw, tx, ty, tz):
    norm = qx*qx + qy*qy + qz*qz + qw*qw
    scale = 2.0 / norm if norm > 1.0e-12 else 0.0
    xx, yy, zz = qx*qx*scale, qy*qy*scale, qz*qz*scale
    xy, xz, yz = qx*qy*scale, qx*qz*scale, qy*qz*scale
    wx, wy, wz = qw*qx*scale, qw*qy*scale, qw*qz*scale
    return [
        [1.0-yy-zz, xy+wz, xz-wy, tx],
        [xy-wz, 1.0-xx-zz, yz+wx, ty],
        [xz+wy, yz-wx, 1.0-xx-yy, tz],
        [0.0, 0.0, 0.0, 1.0],
    ]


def uses_legacy_uv(mesh_name):
    """The Mothra body uses indexed legacy UVs; its wing entries carry direct UVs."""
    name = str(mesh_name or '').lower()
    return 'mothra_mesh_' in name and not name.endswith('wing')


def material_flags(mesh_name, material_blob):
    name = str(mesh_name or '').lower()
    two_sided = bool(len(material_blob) > 7 and material_blob[7] & 0x01)
    black_key = bool(two_sided and name.endswith('wing') or 'tree_' in name)
    color_key = 'decal' in name
    return {
        'two_sided': two_sided,
        'black_key': black_key,
        'color_key': color_key,
        'legacy_uv': uses_legacy_uv(name),
    }


def connected_entries(parsed_files, selected_entry):
    """Return every type-0 main owned by the selected GameCube PWK block."""
    selected_index = next((
        index for index, item in enumerate(parsed_files)
        if item is selected_entry or (
            not item.get('is_resource')
            and item.get('file_type') == 0
            and item.get('file_num') == selected_entry.get('file_num')
        )
    ), -1)
    if selected_index < 0:
        return []
    owner_index = next((
        index for index in range(selected_index - 1, -1, -1)
        if not parsed_files[index].get('is_resource')
        and parsed_files[index].get('file_type') == 16
    ), None)
    if owner_index is None:
        return []
    end = next((
        index for index in range(owner_index + 1, len(parsed_files))
        if not parsed_files[index].get('is_resource')
        and parsed_files[index].get('file_type') == 16
    ), len(parsed_files))
    return [
        item for item in parsed_files[owner_index + 1:end]
        if not item.get('is_resource')
        and item.get('file_type') == 0
        and item.get('file_num') != selected_entry.get('file_num')
    ]


def owner_name(parsed_files, entry):
    index = next((
        index for index, item in enumerate(parsed_files)
        if item is entry or (
            not item.get('is_resource') and item.get('file_type') == 0
            and item.get('file_num') == entry.get('file_num')
        )
    ), -1)
    owner = next((
        parsed_files[position] for position in range(index - 1, -1, -1)
        if not parsed_files[position].get('is_resource')
        and parsed_files[position].get('file_type') == 16
    ), None)
    return Path(str(owner.get('name', '')).replace('\\', '/')).stem if owner else ''


def part_transforms(parser, parsed_files, group):
    """Read GameCube type-3/type-4 node transforms for a connected mesh group."""
    indices = [
        index for index, item in enumerate(parsed_files)
        if any(item is member or (
            item.get('file_num') == member.get('file_num')
            and not item.get('is_resource')
            and item.get('file_type') == 0
        ) for member in group)
    ]
    if not indices:
        return {}
    owner_index = next((
        index for index in range(min(indices) - 1, -1, -1)
        if not parsed_files[index].get('is_resource')
        and parsed_files[index].get('file_type') == 16
    ), None)
    if owner_index is None:
        return {}
    previous_owner = next((
        index for index in range(owner_index - 1, -1, -1)
        if not parsed_files[index].get('is_resource')
        and parsed_files[index].get('file_type') == 16
    ), -1)
    hierarchy_index = next((
        index for index in range(owner_index - 1, previous_owner, -1)
        if not parsed_files[index].get('is_resource')
        and parsed_files[index].get('file_type') == 3
    ), None)
    if hierarchy_index is None:
        return {}
    type4 = next((
        item for item in parsed_files[hierarchy_index + 1:min(len(parsed_files), hierarchy_index + 5)]
        if not item.get('is_resource') and item.get('file_type') == 4
    ), None)
    if type4 is None:
        return {}

    hierarchy = parsed_files[hierarchy_index]
    skeleton = bytes(parser.read_bytes(hierarchy['offset'], hierarchy['size']))
    animation = bytes(parser.read_bytes(type4['offset'], type4['size']))
    strings = [value.decode('latin1', errors='replace') for value in parser._read_pipeworks_string_entries()]
    node_count = struct.unpack_from('>I', skeleton, 0x20)[0]
    node_offsets = struct.unpack_from('>I', skeleton, 0x2C)[0]
    animation_count = struct.unpack_from('>I', animation, 0x2C)[0]
    animation_offsets = struct.unpack_from('>I', animation, 0x30)[0]
    if not (0 < node_count <= animation_count < 512):
        return {}

    nodes = {}
    for table_index in range(node_count):
        relative = struct.unpack_from('>I', skeleton, node_offsets + table_index * 4)[0]
        if relative + 0x10 > len(skeleton):
            continue
        node_index, parent, _child_count, name_index = struct.unpack_from('>4i', skeleton, relative)
        if not (0 <= node_index < animation_count and 0 <= name_index < len(strings)):
            continue
        transform_relative = struct.unpack_from('>I', animation, animation_offsets + node_index * 4)[0]
        if transform_relative + 0x40 > len(animation):
            continue
        tx, ty, tz = struct.unpack_from('>3f', animation, transform_relative + 0x18)
        qx, qy, qz, qw = struct.unpack_from('>4f', animation, transform_relative + 0x30)
        nodes[node_index] = {
            'parent': parent,
            'name': strings[name_index],
            'local': _matrix(qx, qy, qz, qw, tx, ty, tz),
        }

    globals_by_index = {}

    def global_matrix(index):
        if index in globals_by_index:
            return globals_by_index[index]
        node = nodes[index]
        result = node['local']
        if node['parent'] in nodes and node['parent'] != index:
            result = _multiply(global_matrix(node['parent']), result)
        globals_by_index[index] = result
        return result

    named = {
        node['name'].lower(): global_matrix(index)
        for index, node in nodes.items()
    }
    transforms = {}
    primary_file_num = group[0].get('file_num') if group else None
    primary_name = str(group[0].get('name', '')).lower() if group else ''
    for part in group:
        basename = Path(str(part.get('name', '')).replace('\\', '/')).name.lower()
        matches = [(name, matrix) for name, matrix in named.items() if basename.endswith(name)]
        if matches:
            matrix = max(matches, key=lambda match: len(match[0]))[1]
            if part.get('file_num') == primary_file_num:
                matrix = [
                    [1.0, 0.0, 0.0, matrix[0][3]],
                    [0.0, 1.0, 0.0, matrix[1][3]],
                    [0.0, 0.0, 1.0, matrix[2][3]],
                    [0.0, 0.0, 0.0, 1.0],
                ]
            elif 'mothra_mesh_' in primary_name and basename.endswith('wing'):
                matrix = [list(row) for row in matrix]
                attachment_z = matrix[2][3]
                matrix[1] = list(matrix[2])
                matrix[2] = [0.0, 0.0, 0.0, attachment_z]
            transforms[part.get('file_num')] = matrix
    return transforms
