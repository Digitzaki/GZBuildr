#!/usr/bin/env python3
"""Export/import editable Pipeworks type-3/type-4 skeleton rows."""

from __future__ import annotations

import argparse
import importlib.util
import re
import shutil
import struct
from pathlib import Path


ROW_RE = re.compile(r"^@0x([0-9A-Fa-f]+)\s+([A-Za-z0-9_\[\]xXa-fA-F]+)\s+(.+?)\s+=\s+(.*)$")


def load_monster_tool():
    here = Path(__file__).resolve().parent
    candidate = here / "monster_data_txt_tool.py"
    spec = importlib.util.spec_from_file_location("gzbuildr_monster_data_txt_tool", candidate)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Could not load {candidate}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


MD = load_monster_tool()


def endian_prefix(endian: str) -> str:
    return ">" if endian == "big" else "<"


def u32e(data: bytes | bytearray, offset: int, endian: str = "little") -> int:
    return struct.unpack_from(endian_prefix(endian) + "I", data, offset)[0]


def f32e(data: bytes | bytearray, offset: int, endian: str = "little") -> float:
    return struct.unpack_from(endian_prefix(endian) + "f", data, offset)[0]


def u32(data: bytes | bytearray, offset: int) -> int:
    return u32e(data, offset, "little")


def f32(data: bytes | bytearray, offset: int) -> float:
    return f32e(data, offset, "little")


def put_u32(data: bytearray, offset: int, value: int) -> None:
    struct.pack_into("<I", data, offset, value & 0xFFFFFFFF)


def put_f32(data: bytearray, offset: int, value: float) -> None:
    struct.pack_into("<f", data, offset, float(value))


def clean_label(value: str) -> str:
    return MD.clean_label(value).strip("_") or "Node"


def quote_text(value: str) -> str:
    if any(ch.isspace() for ch in value) or value == "":
        return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'
    return value


def strip_inline_comment(value: str) -> str:
    return value.split(" #", 1)[0].strip()


def parse_string_value(value: str, strings: list[str]) -> int:
    value = strip_inline_comment(value).strip()
    if value.startswith("s:"):
        value = value[2:].strip()
    if value in strings:
        return strings.index(value)
    prefixed = "000" + value
    if prefixed in strings:
        return strings.index(prefixed)
    stripped_lookup = {MD.strip_ps2_prefix(item): index for index, item in enumerate(strings)}
    if value in stripped_lookup:
        return stripped_lookup[value]
    raise ValueError(f"Unknown CMP string: {value}")


def backup_path(path: Path) -> Path:
    candidate = path.with_name(path.name + ".bak")
    if not candidate.exists():
        return candidate
    index = 1
    while True:
        candidate = path.with_name(path.name + f".bak{index}")
        if not candidate.exists():
            return candidate
        index += 1


def skeleton_entries(entries: list[dict], file_type: int | None = 3) -> list[dict]:
    return [
        entry
        for entry in entries
        if (file_type is None or int(entry.get("file_type", -1)) == file_type)
        and "SKELETON" in str(entry.get("name", "")).upper()
    ]


def choose_skeleton_entry(entries: list[dict], entry_name: str | None = None, file_type: int | None = 3) -> dict:
    skels = skeleton_entries(entries, file_type)
    if not skels:
        type_text = "type-3/type-4" if file_type is None else f"type-{file_type}"
        raise RuntimeError(f"CMP has no {type_text} skeleton entry")
    if entry_name:
        wanted = entry_name.lower()
        for entry in skels:
            if wanted in str(entry.get("name", "")).lower():
                return entry
        raise RuntimeError(f"No type-3 skeleton entry matched {entry_name!r}")
    return skels[0]


def parse_bundle_any(bundle_path: Path):
    data = bytearray(bundle_path.read_bytes())
    parser = MD.PipeworksParser(bundle_path)
    entries = parser.parse_from_data(bytes(data))
    strings = parser.read_strings()
    endian = "big" if getattr(parser, "is_big_endian", False) else "little"
    return data, parser, entries, strings, endian


def strip_node_prefix(value: str) -> str:
    return MD.strip_ps2_prefix(value)


def is_skeleton_node_name(value: str) -> bool:
    return MD.is_ps2_skeleton_node_name(value)


def skeleton_node_names(data: bytes | bytearray, entries: list[dict], strings: list[str], entry: dict, endian: str = "little") -> dict[int, str]:
    name = Path(str(entry.get("name", ""))).name
    if endian == "little":
        return MD.ps2_skeleton_node_names(data, entries, strings, name)

    start = int(entry.get("data_offset", entry.get("offset", 0)))
    size = int(entry.get("data_size", entry.get("size", 0)))
    if size < 0x40:
        return {}
    try:
        node_count = u32e(data, start + 0x20, endian)
        node_offset_table = u32e(data, start + 0x2C, endian)
    except Exception:
        return {}
    if not (0 < node_count < 512 and 0x40 <= node_offset_table <= size - node_count * 4):
        return {}
    ordered: dict[int, str] = {}
    for index in range(node_count):
        record_rel = u32e(data, start + node_offset_table + index * 4, endian)
        if not (0x40 <= record_rel <= size - 0x10):
            continue
        name_id = u32e(data, start + record_rel + 0x0C, endian)
        if not (0 <= name_id < len(strings)):
            continue
        value = strings[name_id]
        if not is_skeleton_node_name(value):
            continue
        ordered[index] = strip_node_prefix(value)
    return ordered


def skeleton_span(entry: dict) -> tuple[int, int]:
    return int(entry.get("data_offset", entry.get("offset", 0))), int(entry.get("size", 0))


def skeleton_name_ref_rows(blob: bytes | bytearray, strings: list[str], start: int, end: int, endian: str = "little") -> list[tuple[int, str]]:
    rows: list[tuple[int, str]] = []
    seen_offsets: set[int] = set()
    for rel in range(max(0, start), min(len(blob), end), 4):
        raw = u32e(blob, rel, endian)
        if not (0 <= raw < len(strings)):
            continue
        value = strings[raw]
        if not is_skeleton_node_name(value):
            continue
        if rel in seen_offsets:
            continue
        seen_offsets.add(rel)
        rows.append((rel, value))
    return rows


HEADER_FIELDS = {
    0x00: "MagicOrZero",
    0x04: "VersionMajor",
    0x08: "VersionMinor",
    0x1C: "NodeRecordTable",
    0x20: "NodeCount",
    0x24: "ConstraintCount",
    0x28: "SkeletonSize",
    0x2C: "NodeOffsetTable",
    0x30: "SortedNodeOffsetTable",
    0x34: "PairCount",
    0x38: "PairTable",
    0x3C: "TransformTable",
}


MATRIX_FIELDS = [
    "Matrix00", "Matrix01", "Matrix02", "Matrix03",
    "Matrix10", "Matrix11", "Matrix12", "Matrix13",
    "Matrix20", "Matrix21", "Matrix22", "Matrix23",
    "PositionX", "PositionY", "PositionZ", "PositionW",
    "QuaternionX", "QuaternionY", "QuaternionZ", "QuaternionW",
]


WII_TRANSFORM_MATRIX_FIELDS = [
    "MatrixXX", "MatrixXY", "MatrixXZ", "MatrixXW",
    "MatrixYX", "MatrixYY", "MatrixYZ", "MatrixYW",
    "MatrixZX", "MatrixZY", "MatrixZZ", "MatrixZW",
    "PositionX", "PositionY", "PositionZ", "PositionW",
]


WII_NODE_RECORD_FIELDS = [
    (0x00, "int", "NodeIndex"),
    (0x04, "int", "ParentNodeIndex"),
    (0x08, "int", "ChildNodeIndex"),
    (0x0C, "string", "Name"),
    (0x10, "float", "QuaternionX"),
    (0x14, "float", "QuaternionY"),
    (0x18, "float", "QuaternionZ"),
    (0x1C, "float", "QuaternionW"),
    (0x20, "float", "LocalPositionX"),
    (0x24, "float", "LocalPositionY"),
    (0x28, "float", "LocalPositionZ"),
    (0x2C, "int", "Flags"),
    (0x30, "int", "ChildRecordOffsetA"),
    (0x34, "int", "ChildRecordOffsetB"),
    (0x38, "int", "ChildRecordOffsetC"),
    (0x3C, "int", "ChildRecordOffsetD"),
]


TYPE4_HEADER_FIELDS = {
    0x00: ("int", "MagicOrZero"),
    0x04: ("int", "VersionMajor"),
    0x08: ("int", "VersionMinor"),
    0x0C: ("int", "ResourceKind"),
    0x1C: ("float", "DurationOrRate"),
    0x20: ("int", "TrackSetCount"),
    0x24: ("int", "Skeleton4Size"),
    0x28: ("int", "FrameOrDataCount"),
    0x2C: ("int", "NodeCount"),
    0x30: ("int", "NodeRecordPointerTable"),
}


TYPE4_NODE_FIELDS = [
    (0x00, "int", "NodeIndex"),
    (0x04, "float", "NodeDistance"),
    (0x08, "int", "PositionKeyCount"),
    (0x0C, "int", "RotationKeyCount"),
    (0x10, "int", "ScaleKeyCount"),
    (0x14, "float", "ScaleX"),
    (0x18, "float", "ScaleY"),
    (0x1C, "int", "PositionBlockOffset"),
    (0x20, "int", "RotationBlockOffset"),
    (0x24, "float", "PositionA.X"),
    (0x28, "float", "PositionA.Y"),
    (0x2C, "float", "PositionA.Z"),
    (0x30, "float", "PositionB.X"),
    (0x34, "float", "PositionB.Y"),
    (0x38, "float", "PositionB.Z"),
    (0x3C, "float", "RotationBasis00"),
    (0x40, "float", "RotationBasis01"),
    (0x44, "float", "RotationBasis02"),
    (0x48, "float", "RotationBasis10"),
    (0x4C, "float", "RotationBasis11"),
    (0x50, "float", "RotationBasis12"),
    (0x54, "float", "RotationBasis20"),
    (0x58, "float", "RotationBasis21"),
    (0x5C, "float", "RotationBasis22"),
]


def export_txt(cmp_path: Path, out_path: Path, entry_name: str | None = None) -> None:
    data, _parser, entries, strings, endian = parse_bundle_any(cmp_path)
    entry = choose_skeleton_entry(entries, entry_name, None if entry_name else 3)
    if int(entry.get("file_type", 3)) == 4:
        export_type4_txt(cmp_path, out_path, entry_name)
        return
    base, size = skeleton_span(entry)
    blob = data[base : base + size]
    node_count = u32e(blob, 0x20, endian)
    node_table = u32e(blob, 0x1C, endian)
    node_offsets = u32e(blob, 0x2C, endian)
    sorted_offsets = u32e(blob, 0x30, endian)
    pair_table = u32e(blob, 0x38, endian)
    transform_table = u32e(blob, 0x3C, endian)
    names = skeleton_node_names(data, entries, strings, entry, endian)
    transform_record_size = (size - transform_table) // node_count if node_count and transform_table < size else 0

    lines: list[str] = [
        "# Pipeworks type-3 skeleton text export",
        f"# SourceBundle={cmp_path}",
        f"# SourceCMP={cmp_path}" if endian == "little" else f"# SourceBDG={cmp_path}",
        f"# SkeletonEntry={entry.get('name')}",
        f"# SkeletonOffset=0x{base:X}",
        f"# SkeletonSize=0x{size:X}",
        f"# Endian={endian}",
        "# Format: @offset <type> <name> = <value>",
        "# Transform notes: Position*/Quaternion* names are inferred from the 80-byte per-node transform block.",
        "",
        "[Skeleton.Header]",
    ]
    for rel, name in HEADER_FIELDS.items():
        if rel + 4 <= size:
            lines.append(f"@0x{rel:06X} int          Header.{name} = {u32e(blob, rel, endian)}")

    extra_names = [(index, name) for index, name in sorted(names.items()) if index >= node_count]
    if extra_names:
        lines.extend([
            "",
            "[Skeleton.AttachmentNodes]",
            "# Context only; these names are referenced by the skeleton resources but are outside Header.NodeCount.",
            "# They do not have type-3 transform records in this file.",
        ])
        for index, name in extra_names:
            lines.append(f"AttachmentNode{index:03d} {quote_text(name)}")

    name_ref_end = node_offsets if node_offsets else min(size, 0x800)
    name_refs = skeleton_name_ref_rows(blob, strings, node_table, name_ref_end, endian)
    if name_refs:
        lines.extend([
            "",
            "[Skeleton.NameRefs]",
            "# Editable string-table references stored in the type-3 skeleton name/lookup block.",
            "# These include attachment-style names such as Lift_Node even when they have no transform record.",
        ])
        seen_labels: dict[str, int] = {}
        for rel, value in name_refs:
            clean = clean_label(strip_node_prefix(value))
            count = seen_labels.get(clean, 0)
            seen_labels[clean] = count + 1
            suffix = f"_{count:02d}" if count else ""
            lines.append(f"@0x{rel:06X} string       Skeleton.NameRef.{clean}{suffix} = {value}")

    if endian == "big" and node_table and node_offsets and node_table < node_offsets:
        lines.extend(["", "[Skeleton.NodeRecords]"])
        node_record_rels: list[int] = []
        for index in range(node_count):
            rel = node_offsets + index * 4
            if rel + 4 <= size:
                record_rel = u32e(blob, rel, endian)
                if node_table <= record_rel < node_offsets:
                    node_record_rels.append(record_rel)
        sorted_record_rels = sorted(set(node_record_rels))
        for index in range(node_count):
            record_rel = u32e(blob, node_offsets + index * 4, endian) if node_offsets + index * 4 + 4 <= size else 0
            if not (node_table <= record_rel < node_offsets):
                continue
            next_record_rel = next((candidate for candidate in sorted_record_rels if candidate > record_rel), node_offsets)
            record_end = min(next_record_rel, node_offsets)
            node_name = clean_label(names.get(index, f"Node{index:03d}"))
            lines.append("")
            lines.append(f"## NodeRecord {index:03d} {node_name}")
            for field_rel, kind, field_name in WII_NODE_RECORD_FIELDS:
                absolute_rel = record_rel + field_rel
                if absolute_rel + 4 > record_end:
                    continue
                if kind == "float":
                    value = f32e(blob, absolute_rel, endian)
                elif kind == "string":
                    raw = u32e(blob, absolute_rel, endian)
                    value = strings[raw] if 0 <= raw < len(strings) else f"string_{raw}"
                else:
                    value = u32e(blob, absolute_rel, endian)
                lines.append(f"@0x{absolute_rel:06X} {kind:<12} NodeRecord.{node_name}.{field_name} = {value!r}" if kind == "float" else f"@0x{absolute_rel:06X} {kind:<12} NodeRecord.{node_name}.{field_name} = {value}")

    if node_offsets and node_offsets + node_count * 4 <= size:
        lines.extend(["", "[Skeleton.NodeOffsets]"])
        for index in range(node_count):
            rel = node_offsets + index * 4
            node_rel = u32e(blob, rel, endian)
            node_name = clean_label(names.get(index, f"Node{index:03d}"))
            lines.append(f"@0x{rel:06X} int          NodeOffset.{node_name} = {node_rel}")

    if sorted_offsets and sorted_offsets + node_count * 4 <= size:
        lines.extend(["", "[Skeleton.SortedNodeOffsets]"])
        for index in range(node_count):
            rel = sorted_offsets + index * 4
            node_rel = u32e(blob, rel, endian)
            node_name = clean_label(names.get(index, f"Node{index:03d}"))
            lines.append(f"@0x{rel:06X} int          SortedNodeOffset.{index:03d}.{node_name} = {node_rel}")

    if pair_table and pair_table < size:
        pair_end = transform_table if transform_table > pair_table else min(size, pair_table + 0x100)
        lines.extend(["", "[Skeleton.Pairs]"])
        for rel in range(pair_table, pair_end, 4):
            raw = u32e(blob, rel, endian)
            hi = (raw >> 16) & 0xFFFF
            lo = raw & 0xFFFF
            lines.append(f"@0x{rel:06X} u16x2        Pair.{(rel - pair_table) // 4:03d} = {hi}, {lo}")

    if endian == "big" and transform_record_size >= 64:
        lines.extend(["", "[Skeleton.TransformMatrix]"])
        for index in range(node_count):
            node_name = clean_label(names.get(index, f"Node{index:03d}"))
            rel = transform_table + index * transform_record_size
            if rel + 0x40 > size:
                continue
            lines.append("")
            lines.append(f"## TransformMatrix Node {index:03d} {node_name}")
            for field_index, field_name in enumerate(WII_TRANSFORM_MATRIX_FIELDS):
                field_rel = rel + field_index * 4
                lines.append(f"@0x{field_rel:06X} float        TransformMatrix.{node_name}.{field_name} = {float(f32e(blob, field_rel, endian))!r}")
    elif transform_record_size >= 80:
        lines.extend(["", "[Skeleton.Transforms]"])
        for index in range(node_count):
            node_name = clean_label(names.get(index, f"Node{index:03d}"))
            rel = transform_table + index * transform_record_size
            lines.append("")
            lines.append(f"## Node {index:03d} {node_name}")
            for field_index, field_name in enumerate(MATRIX_FIELDS):
                field_rel = rel + field_index * 4
                lines.append(f"@0x{field_rel:06X} float        Transform.{node_name}.{field_name} = {float(f32e(blob, field_rel, endian))!r}")

    if names:
        lines.extend(["", "[Skeleton.NodeNames]", "# Context only; names come from the CMP skeleton resources."])
        for index, name in sorted(names.items()):
            lines.append(f"Node{index:03d} {quote_text(name)}")

    out_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"Wrote {out_path}")
    print(f"Exported {entry.get('name')} ({node_count} nodes, transform record size {transform_record_size}, {endian}-endian).")


def export_type4_txt(cmp_path: Path, out_path: Path, entry_name: str | None = None) -> None:
    data, _parser, entries, strings, endian = parse_bundle_any(cmp_path)
    entry = choose_skeleton_entry(entries, entry_name, 4)
    base, size = skeleton_span(entry)
    blob = data[base : base + size]
    node_count = u32e(blob, 0x2C, endian)
    pointer_table = u32e(blob, 0x30, endian)
    names = skeleton_node_names(data, entries, strings, entry, endian)

    lines: list[str] = [
        "# Pipeworks type-4 skeleton text export",
        f"# SourceBundle={cmp_path}",
        f"# SourceCMP={cmp_path}" if endian == "little" else f"# SourceBDG={cmp_path}",
        f"# SkeletonEntry={entry.get('name')}",
        f"# SkeletonOffset=0x{base:X}",
        f"# SkeletonSize=0x{size:X}",
        f"# Endian={endian}",
        "# Format: @offset <type> <name> = <value>",
        "# Type-4 notes: this is not the type-3 bind-pose skeleton. It stores one 0x60-byte record per node.",
        "# PositionA/PositionB/RotationBasis names are structural labels; real engine field names are not confirmed.",
        "",
        "[Skeleton4.Header]",
    ]
    for rel, (kind, name) in TYPE4_HEADER_FIELDS.items():
        if rel + 4 > size:
            continue
        value = f32e(blob, rel, endian) if kind == "float" else u32e(blob, rel, endian)
        lines.append(f"@0x{rel:06X} {kind:<12} Header.{name} = {value!r}")

    extra_names = [(index, name) for index, name in sorted(names.items()) if index >= node_count]
    if extra_names:
        lines.extend([
            "",
            "[Skeleton4.AttachmentNodes]",
            "# Context only; these names are referenced by the skeleton resources but are outside Header.NodeCount.",
            "# They do not have type-4 node records in this file.",
        ])
        for index, name in extra_names:
            lines.append(f"AttachmentNode{index:03d} {quote_text(name)}")

    if pointer_table and pointer_table + node_count * 4 <= size:
        lines.extend(["", "[Skeleton4.NodeRecordPointers]"])
        pointers = []
        for index in range(node_count):
            rel = pointer_table + index * 4
            ptr = u32e(blob, rel, endian)
            pointers.append(ptr)
            node_name = clean_label(names.get(index, f"Node{index:03d}"))
            lines.append(f"@0x{rel:06X} int          NodeRecordPointer.{node_name} = {ptr}")

        lines.extend(["", "[Skeleton4.NodeRecords]"])
        for index, rel in enumerate(pointers):
            if rel <= 0 or rel + 0x60 > size:
                continue
            node_index = u32e(blob, rel, endian)
            node_name = clean_label(names.get(node_index, names.get(index, f"Node{index:03d}")))
            lines.append("")
            lines.append(f"## Node {node_index:03d} {node_name}")
            for field_rel, kind, field_name in TYPE4_NODE_FIELDS:
                absolute_rel = rel + field_rel
                value = f32e(blob, absolute_rel, endian) if kind == "float" else u32e(blob, absolute_rel, endian)
                lines.append(f"@0x{absolute_rel:06X} {kind:<12} Skeleton4.{node_name}.{field_name} = {value!r}")

    if names:
        lines.extend(["", "[Skeleton4.NodeNames]", "# Context only; names come from the CMP skeleton resources."])
        for index, name in sorted(names.items()):
            lines.append(f"Node{index:03d} {quote_text(name)}")

    out_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"Wrote {out_path}")
    print(f"Exported {entry.get('name')} ({node_count} node records).")


def parse_value(kind: str, value: str, strings: list[str] | None = None, endian: str = "little") -> bytes:
    value = strip_inline_comment(value)
    if kind == "string":
        if strings is None:
            raise ValueError("String edits need bundle string-table context")
        return parse_string_value(value, strings).to_bytes(4, endian)
    if kind == "float":
        return struct.pack(endian_prefix(endian) + "f", float(value))
    if kind in {"int", "ref"}:
        return int(value, 0).to_bytes(4, endian, signed=False)
    if kind == "u16x2":
        parts = [part.strip() for part in value.split(",")]
        if len(parts) != 2:
            raise ValueError(f"u16x2 needs two comma-separated values: {value}")
        hi, lo = (int(part, 0) & 0xFFFF for part in parts)
        return ((hi << 16) | lo).to_bytes(4, endian)
    raise ValueError(f"Unsupported skeleton row type {kind}")


def metadata_from_txt(txt_path: Path) -> dict[str, str]:
    meta: dict[str, str] = {}
    for line in txt_path.read_text(encoding="utf-8").splitlines():
        if line.startswith("#") and "=" in line:
            key, value = line[1:].split("=", 1)
            meta[key.strip()] = value.strip()
    return meta


def endian_from_txt(txt_path: Path, default: str = "little") -> str:
    value = metadata_from_txt(txt_path).get("Endian", default).strip().lower()
    return "big" if value == "big" else "little"


def collect_txt_changes(txt_path: Path, data: bytes | bytearray, base: int, size: int, strings: list[str] | None = None, endian: str = "little") -> dict[int, tuple[bytes, str, str]]:
    wanted: dict[int, tuple[bytes, str, str]] = {}
    conflicts: list[str] = []
    for line in txt_path.read_text(encoding="utf-8").splitlines():
        match = ROW_RE.match(line.strip())
        if not match:
            continue
        rel = int(match.group(1), 16)
        kind = match.group(2)
        label = match.group(3).strip()
        value = match.group(4).strip()
        if kind not in {"float", "int", "ref", "u16x2", "string"} or rel < 0 or rel + 4 > size:
            continue
        new_bytes = parse_value(kind, value, strings, endian)
        old_bytes = bytes(data[base + rel : base + rel + 4])
        if old_bytes == new_bytes:
            continue
        previous = wanted.get(rel)
        if previous and previous[0] != new_bytes:
            conflicts.append(f"@0x{rel:06X} has conflicting edits: {previous[1]} vs {value}")
            continue
        wanted[rel] = (new_bytes, value, label)
    if conflicts:
        raise RuntimeError("Conflicting duplicate-offset edits:\n  " + "\n  ".join(conflicts))
    return wanted


def apply_txt_to_skeleton_blob(txt_path: Path, skeleton_blob: bytes | bytearray, strings: list[str] | None = None) -> bytes:
    data = bytearray(skeleton_blob)
    endian = endian_from_txt(txt_path)
    wanted = collect_txt_changes(txt_path, data, 0, len(data), strings, endian)
    for rel, (new_bytes, _value, _label) in wanted.items():
        data[rel : rel + 4] = new_bytes
    return bytes(data)


def import_txt(txt_path: Path, cmp_override: Path | None = None, dry_run: bool = False) -> None:
    meta = metadata_from_txt(txt_path)
    cmp_path = cmp_override or Path(meta.get("SourceBundle") or meta.get("SourceCMP") or meta.get("SourceBDG") or "")
    if not cmp_path.exists():
        raise RuntimeError("Skeleton TXT does not point at an existing SourceBundle/SourceCMP/SourceBDG; pass --cmp")
    data, _parser, entries, strings, endian = parse_bundle_any(cmp_path)
    endian = meta.get("Endian", endian).strip().lower()
    endian = "big" if endian == "big" else "little"
    entry = choose_skeleton_entry(entries, meta.get("SkeletonEntry"), None if meta.get("SkeletonEntry") else 3)
    base, size = skeleton_span(entry)
    wanted = collect_txt_changes(txt_path, data, base, size, strings, endian)
    if not wanted:
        print("No changed editable skeleton values found.")
        return
    print(f"{'Would apply' if dry_run else 'Applying'} {len(wanted)} skeleton changes to {cmp_path}:")
    for rel, (_new, value, label) in list(sorted(wanted.items()))[:80]:
        print(f"  type3+0x{rel:06X} {label} -> {value}")
    if dry_run:
        return
    backup = backup_path(cmp_path)
    shutil.copy2(cmp_path, backup)
    for rel, (new_bytes, _value, _label) in wanted.items():
        data[base + rel : base + rel + 4] = new_bytes
    cmp_path.write_bytes(data)
    print(f"Wrote {cmp_path}")
    print(f"Backup: {backup}")


def cli_main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Export/import editable PS2 CMP type-3 skeleton rows.")
    sub = parser.add_subparsers(dest="command", required=True)
    exp = sub.add_parser("export")
    exp.add_argument("cmp", type=Path)
    exp.add_argument("--out", type=Path)
    exp.add_argument("--entry", help="Skeleton entry name substring")
    exp.add_argument("--type", type=int, choices=(3, 4), default=3, help="Skeleton file type to export when --entry is omitted")
    imp = sub.add_parser("import")
    imp.add_argument("txt", type=Path)
    imp.add_argument("--cmp", type=Path)
    imp.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)
    if args.command == "export":
        out = args.out or args.cmp.with_name(args.cmp.stem + ("_Skeleton4.txt" if args.type == 4 else "_Skeleton.txt"))
        entry = args.entry
        if not entry and args.type == 4:
            entry = "4/"
        export_txt(args.cmp, out, entry)
    else:
        import_txt(args.txt, args.cmp, args.dry_run)
    return 0


if __name__ == "__main__":
    raise SystemExit(cli_main())
