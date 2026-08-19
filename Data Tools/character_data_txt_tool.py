#!/usr/bin/env python3
from __future__ import annotations

import argparse
import re
import shutil
import struct
import sys
import zipfile
from datetime import datetime
from pathlib import Path
from tkinter import Tk, filedialog


def app_dir() -> Path:
    return Path(__file__).resolve().parent


TOOL_DIR = app_dir()
ROOT = TOOL_DIR.parent
BACKUP_ROOT = ROOT / "backups"
GAME_DIR = ROOT / "DATA" / "files" / "Game"

ROW_RE = re.compile(r"^@0x([0-9A-Fa-f]+)\s+([a-zA-Z0-9_]+)\s+(.+?)\s+=\s+(.*)$")
NAMED_ROW_RE = re.compile(r"^(.+?)\s*=\s*(.*?)\s+#\s*@0x([0-9A-Fa-f]+)(?:\s+([a-zA-Z0-9_]+))?\b")
META_RE = re.compile(r"^#\s*([^=]+?)=(.*)$")
REF_COMMENT_RE = re.compile(r"#\s*@0x([0-9A-Fa-f]+)\b")

CHANIM_TYPE = "ChAnimResource"
CHANIM_RECORD_SIZE = 0x64

CHANIM_STRING_FIELDS = {
    0x08: "Type",
    0x0C: "ResourceName",
    0x30: "Animation",
}

CHANIM_F32_FIELDS = {
    0x44: "Speed",
    0x4C: "EventEndTime",
}

CHANIM_REF_FIELDS = {
    0x40: "EventDirectory",
}

CHANIM_U32_FIELDS = {
    0x00: "ObjectHeader.TypeTag",
    0x04: "ObjectHeader.LayoutTag",
    0x10: "Mask",
    0x14: "BodyFlags",
    0x18: "BlendInFrames",
    0x1C: "BlendOutFrames",
    0x20: "StartFrame",
    0x24: "EndFrame",
    0x28: "LoopStartFrame",
    0x2C: "LoopEndFrame",
    0x34: "AnimationFlags",
    0x38: "PlaybackMode",
    0x3C: "Flags",
    0x48: "SpeedFlags",
    0x50: "TransitionMode",
    0x54: "TransitionParam",
    0x58: "BlendGroup",
    0x5C: "QueueMode",
    0x60: "ResourceFlags",
}

KNOWN_POINTER_DIRECTORIES = {
    0x44D8: ("ScriptThreadDirectory", "ScriptThread"),
    0x79C0: ("StateConditionDirectory", "StateCondition"),
    0xDB6C: ("AnimationDirectory", "AnimationRecord"),
    0x12960: ("ActionDataDirectory", "ActionData"),
    0x13988: ("ReactionRootDirectory", "ReactionRoot"),
    0x16264: ("ActionLinkDirectory", "ActionLink"),
    0x16384: ("ComponentDirectory", "Component"),
}

SCRIPT_TABLE_NAMES = {
    0x68: "EventCondition",
    0x6C: "EventAction",
    0x70: "EventCommand",
    0x74: "EventOperandValue",
}

GENERIC_RECORD_NAMES = {
    "Active_Speed",
    "Acceleration",
    "Critical_Scale",
    "Movement",
    "AIClassName",
    "ActivateFunc",
}

DEFAULT_CONTROLLER_PREFIX = "Default_Controller.ChPlayerController"


def load_light_bdg():
    roots = [
        TOOL_DIR,
        ROOT,
        Path(sys.executable).resolve().parent if getattr(sys, "frozen", False) else None,
        Path.cwd(),
        Path(getattr(sys, "_MEIPASS", "")) if getattr(sys, "_MEIPASS", "") else None,
    ]
    candidates = []
    for root in roots:
        if root is None:
            continue
        candidates.extend([
            root / "light_bdg.py",
            root / "PRX_Tools" / "light_bdg.py",
            root / "Data Tools" / "light_bdg.py",
        ])
    seen = set()
    for path in candidates:
        key = str(path).lower()
        if key in seen:
            continue
        seen.add(key)
        if path.exists():
            sys.path.insert(0, str(path.parent))
            from light_bdg import PipeworksParser

            return PipeworksParser
    searched = "\n  ".join(str(path) for path in candidates if str(path).lower() in seen)
    raise ModuleNotFoundError(f"Could not find light_bdg.py. Searched:\n  {searched}")


PipeworksParser = load_light_bdg()


def ask(prompt: str, default: str | None = None) -> str:
    suffix = f" [{default}]" if default else ""
    value = input(f"{prompt}{suffix}: ").strip()
    return value or (default or "")


def pick_open_file(title: str, filetypes: list[tuple[str, str]], initialdir: Path | None = None) -> Path:
    root = Tk()
    root.withdraw()
    root.attributes("-topmost", True)
    try:
        selected = filedialog.askopenfilename(
            title=title,
            initialdir=str(initialdir or ROOT),
            filetypes=filetypes,
        )
    finally:
        root.destroy()
    if not selected:
        raise SystemExit("No file selected.")
    return Path(selected)


def pick_save_file(title: str, default_name: str, filetypes: list[tuple[str, str]]) -> Path:
    root = Tk()
    root.withdraw()
    root.attributes("-topmost", True)
    try:
        selected = filedialog.asksaveasfilename(
            title=title,
            initialdir=str(ROOT),
            initialfile=default_name,
            defaultextension=".txt",
            filetypes=filetypes,
        )
    finally:
        root.destroy()
    if not selected:
        raise SystemExit("No output file selected.")
    return Path(selected)


def u32(data: bytes | bytearray, offset: int) -> int:
    return struct.unpack_from(">I", data, offset)[0]


def put_u32(data: bytearray, offset: int, value: int) -> None:
    struct.pack_into(">I", data, offset, value & 0xFFFFFFFF)


def f32(data: bytes | bytearray, offset: int) -> float:
    return struct.unpack_from(">f", data, offset)[0]


def put_f32(data: bytearray, offset: int, value: float) -> None:
    struct.pack_into(">f", data, offset, float(value))


def parse_bundle(bundle_path: Path):
    data = bytearray(bundle_path.read_bytes())
    parser = PipeworksParser(bundle_path)
    entries = parser.parse_from_data(bytes(data))
    strings = parser.read_strings()
    character_data = next((entry for entry in entries if entry["name"] == "2/Character_Data"), None)
    if character_data is None:
        raise RuntimeError(f"{bundle_path} has no 2/Character_Data entry")
    return data, parser, entries, strings, character_data


def character_data_span(entry: dict) -> tuple[int, int]:
    return int(entry.get("data_offset", entry["offset"])), int(entry.get("data_size", entry["size"]))


def cstr_safe(value: str) -> str:
    return value.replace("\r", " ").replace("\n", " ").strip()


def strip_inline_comment(value: str) -> str:
    return value.split(" #", 1)[0].strip()


def string_value(data: bytes | bytearray, strings: list[str], absolute_offset: int) -> str:
    index = u32(data, absolute_offset)
    if 0 <= index < len(strings):
        return cstr_safe(strings[index])
    return str(index)


def row_value(data: bytes | bytearray, strings: list[str], absolute_offset: int, kind: str) -> str:
    if kind == "string":
        return string_value(data, strings, absolute_offset)
    if kind in {"f32", "float"}:
        return repr(float(f32(data, absolute_offset)))
    if kind in {"u32", "word"}:
        return f"0x{u32(data, absolute_offset):08X}"
    if kind in {"int", "ref"}:
        raw = u32(data, absolute_offset)
        return str(raw if raw < 0x80000000 else raw - 0x100000000)
    if kind == "u16x2":
        return u16x2_text(u32(data, absolute_offset))
    if kind == "u8x4":
        return u8x4_text(u32(data, absolute_offset))
    if kind == "bool":
        return "true" if u32(data, absolute_offset) else "false"
    raise ValueError(kind)


def editable_value(data: bytes | bytearray, strings: list[str], absolute_offset: int, kind: str, force: str | None = None) -> str:
    raw = u32(data, absolute_offset)
    if force == "string":
        return f"s:{string_value(data, strings, absolute_offset)}"
    if force == "f32":
        return f"f:{float(f32(data, absolute_offset))!r}"
    if kind == "string":
        return f"s:{string_value(data, strings, absolute_offset)}"
    if kind == "f32":
        return f"f:{float(f32(data, absolute_offset))!r}"
    return f"0x{raw:08X}"


def u16x2_text(raw: int) -> str:
    return f"{(raw >> 16) & 0xFFFF}, {raw & 0xFFFF}"


def u8x4_text(raw: int) -> str:
    return ", ".join(str((raw >> shift) & 0xFF) for shift in (24, 16, 8, 0))


def looks_like_u16x2(raw: int) -> bool:
    hi = (raw >> 16) & 0xFFFF
    lo = raw & 0xFFFF
    return hi <= 0x0100 and lo <= 0x0100 and (hi != 0 or lo != 0) and lo in {hi + 1, 0, 0xFFFF}


def looks_like_u8x4(raw: int) -> bool:
    vals = [(raw >> shift) & 0xFF for shift in (24, 16, 8, 0)]
    return len(set(vals)) <= 3 and all(v in {0, 1, 2, 3, 6, 9, 15, 0xFF} for v in vals) and any(v not in {0, 0xFF} for v in vals)


def looks_like_float(data: bytes | bytearray, absolute: int) -> bool:
    raw = u32(data, absolute)
    value = f32(data, absolute)
    exponent = (raw >> 23) & 0xFF
    return raw != 0 and 0x70 <= exponent <= 0x8E and abs(value) < 1000000.0


def clean_label(value: str) -> str:
    value = cstr_safe(value).replace("/", "_").replace("\\", "_")
    return re.sub(r"\s+", "_", value).strip("._") or "Value"


def looks_like_mask_group_header(data: bytes | bytearray, strings: list[str], base: int, size: int, rel: int) -> bool:
    if rel + 0x14 > size:
        return False
    name_id = u32(data, base + rel)
    if not (0 <= name_id < len(strings) and strings[name_id]):
        return False
    name = strings[name_id]
    if name.startswith("."):
        return False
    props_ptr = u32(data, base + rel + 0x04)
    channel_ptr = u32(data, base + rel + 0x08)
    index_ptr = u32(data, base + rel + 0x0C)
    mode_count = u32(data, base + rel + 0x10)
    mode = mode_count >> 16
    count = mode_count & 0xFFFF
    return (
        props_ptr == rel + 0x14
        and channel_ptr == props_ptr + 0x0C
        and index_ptr == channel_ptr + 0x48
        and mode in {0, 1}
        and 0 < count < 0x100
        and index_ptr + ((count + 1) // 2) * 4 <= size
    )


def scan_mask_groups(data: bytes | bytearray, strings: list[str], base: int, size: int) -> list[dict[str, object]]:
    groups: list[dict[str, object]] = []
    for rel in range(0, size - 0x20, 4):
        if not looks_like_mask_group_header(data, strings, base, size, rel):
            continue
        mode_count = u32(data, base + rel + 0x10)
        groups.append(
            {
                "rel": rel,
                "name": cstr_safe(strings[u32(data, base + rel)]),
                "prop_rules": u32(data, base + rel + 0x04),
                "channel_mask": u32(data, base + rel + 0x08),
                "index_list": u32(data, base + rel + 0x0C),
                "mode": mode_count >> 16,
                "count": mode_count & 0xFFFF,
            }
        )
    return groups


def mask_group_labels(groups: list[dict[str, object]]) -> tuple[dict[int, str], dict[int, str], set[int]]:
    labels: dict[int, str] = {}
    forced_types: dict[int, str] = {}
    covered: set[int] = set()

    for group in groups:
        rel = int(group["rel"])
        stem = clean_label(str(group["name"]))
        prop_rules = int(group["prop_rules"])
        channel_mask = int(group["channel_mask"])
        index_list = int(group["index_list"])
        count = int(group["count"])
        labels[rel] = f"{stem}.Name"
        labels[rel + 0x04] = f"{stem}.PropertyRules"
        labels[rel + 0x08] = f"{stem}.ChannelMask"
        labels[rel + 0x0C] = f"{stem}.AffectedIndexList"
        labels[rel + 0x10] = f"{stem}.ModeAndIndexCount"
        forced_types[rel] = "string"
        forced_types[rel + 0x04] = "ref"
        forced_types[rel + 0x08] = "ref"
        forced_types[rel + 0x0C] = "ref"
        forced_types[rel + 0x10] = "u16x2"
        covered.update(range(rel, rel + 0x14, 4))

        prop_names = ("PropertyRule0", "PropertyRule1", "FallbackProperty")
        for entry, off in enumerate(range(prop_rules, channel_mask, 4)):
            labels[off] = f"{stem}.{prop_names[entry] if entry < len(prop_names) else f'PropertyRule{entry}'}"
            covered.add(off)

        for entry, off in enumerate(range(channel_mask, index_list, 4)):
            labels[off] = f"{stem}.ChannelMaskWords"
            forced_types[off] = "u8x4"
            covered.add(off)

        index_words = (count + 1) // 2
        for entry in range(index_words):
            off = index_list + entry * 4
            labels[off] = f"{stem}.AffectedChannelIndices"
            forced_types[off] = "u16x2"
            covered.add(off)

    return labels, forced_types, covered


def annotate_mask_group_directory(
    data: bytes | bytearray,
    base: int,
    size: int,
    groups: list[dict[str, object]],
    labels: dict[int, str],
    forced_types: dict[int, str],
) -> None:
    group_by_rel = {int(group["rel"]): clean_label(str(group["name"])) for group in groups}
    if not group_by_rel:
        return
    group_offsets = set(group_by_rel)
    sorted_groups = sorted(group_offsets)
    best_start = None
    best_len = 0
    for rel in range(0, size - 4, 4):
        count = 0
        while rel + count * 4 + 4 <= size and u32(data, base + rel + count * 4) in group_offsets:
            count += 1
        if count > best_len:
            best_start = rel
            best_len = count
    if best_start is None or best_len < min(4, len(sorted_groups)):
        return
    for entry in range(best_len):
        rel = best_start + entry * 4
        target = u32(data, base + rel)
        labels[rel] = f"MaskGroupDirectory.{group_by_rel[target]}"
        forced_types[rel] = "ref"


HEADER_FIELDS = {
    0x00: ("string", "CharacterDataHeader.AmbientAnim2"),
    0x04: ("int", "CharacterDataHeader.Reserved04"),
    0x08: ("int", "CharacterDataHeader.EndOffset"),
    0x0C: ("string", "CharacterDataHeader.BeamFightSwatAction"),
    0x10: ("int", "CharacterDataHeader.Reserved10"),
    0x14: ("float", "CharacterDataHeader.BeamFightValue14"),
    0x18: ("float", "CharacterDataHeader.BeamFightValue18"),
    0x1C: ("int", "CharacterDataHeader.Reserved1C"),
    0x20: ("float", "CharacterDataHeader.BeamFightValue20"),
    0x24: ("float", "CharacterDataHeader.BeamFightValue24"),
    0x28: ("int", "CharacterDataHeader.Reserved28"),
    0x2C: ("int", "CharacterDataHeader.Reserved2C"),
    0x30: ("string", "CharacterDataHeader.BeamFightWinAction"),
    0x34: ("string", "CharacterDataHeader.BeamFightLoseAction"),
    0x38: ("ref", "CharacterDataHeader.MirrorGroup"),
    0x3C: ("string", "CharacterDataHeader.CharacterName"),
    0x40: ("string", "CharacterDataHeader.BaseClass"),
    0x44: ("string", "CharacterDataHeader.DefaultMoveName"),
    0x48: ("string", "CharacterDataHeader.ChargeFxNodeOrName"),
    0x4C: ("string", "CharacterDataHeader.HeadAimNode"),
    0x50: ("string", "CharacterDataHeader.SkeletonName"),
    0x54: ("string", "CharacterDataHeader.RootPvmName"),
    0x58: ("string", "CharacterDataHeader.PropBookName"),
    0x5C: ("string", "CharacterDataHeader.AmbientAnim1"),
    0x60: ("ref", "CharacterDataHeader.MaskGroupDirectory"),
    0x64: ("ref", "CharacterDataHeader.BoneLookupTable"),
    0x68: ("ref", "CharacterDataHeader.ScriptConditionTable"),
    0x6C: ("ref", "CharacterDataHeader.ScriptActionTable"),
    0x70: ("ref", "CharacterDataHeader.ScriptCommandTable"),
    0x74: ("ref", "CharacterDataHeader.ScriptValueTable"),
    0x78: ("u16x2", "CharacterDataHeader.UnknownPair78"),
    0x7C: ("u16x2", "CharacterDataHeader.UnknownPair7C"),
    0xE8: ("int", "CharacterDataHeader.ReservedE8"),
    0xEC: ("int", "CharacterDataHeader.ReservedEC"),
    0xF0: ("string", "CharacterDataHeader.MeshName"),
    0xF4: ("string", "CharacterDataHeader.MeshClass"),
    0xF8: ("int", "CharacterDataHeader.MeshReservedF8"),
    0xFC: ("int", "CharacterDataHeader.MeshReservedFC"),
}


def top_level_labels(data: bytes | bytearray, strings: list[str], base: int, size: int) -> tuple[dict[int, str], dict[int, str], dict[int, str]]:
    labels: dict[int, str] = {}
    forced_types: dict[int, str] = {}
    target_stems: dict[int, str] = {}
    for rel, (kind, label) in HEADER_FIELDS.items():
        if rel + 4 <= size:
            labels[rel] = label
            forced_types[rel] = kind
            if kind == "ref":
                target = u32(data, base + rel)
                if target % 4 == 0 and 0 < target < size:
                    target_stems[target] = clean_label(label.removeprefix("CharacterDataHeader."))

    for rel in range(0x80, 0xE8, 8):
        if rel + 8 > size:
            break
        name_id = u32(data, base + rel)
        target = u32(data, base + rel + 0x04)
        if not (0 <= name_id < len(strings) and strings[name_id] and target % 4 == 0 and 0 < target < size):
            continue
        stem = clean_label(strings[name_id])
        labels[rel] = f"CharacterDataHeader.{stem}.Name"
        labels[rel + 0x04] = f"CharacterDataHeader.{stem}.Value"
        forced_types[rel] = "string"
        forced_types[rel + 0x04] = "ref"
        target_stems[target] = stem
    return labels, forced_types, target_stems


def script_table_spans(data: bytes | bytearray, base: int, size: int) -> list[tuple[int, int, str]]:
    starts: list[tuple[int, str]] = []
    for header_rel, table_name in SCRIPT_TABLE_NAMES.items():
        if header_rel + 4 > size:
            continue
        start = u32(data, base + header_rel)
        if start % 4 == 0 and 0 < start < size:
            starts.append((start, table_name))
    for directory_start in KNOWN_POINTER_DIRECTORIES:
        if 0 < directory_start < size:
            starts.append((directory_start, "DirectoryBoundary"))
    starts = sorted(set(starts))
    spans: list[tuple[int, int, str]] = []
    for index, (start, table_name) in enumerate(starts):
        if table_name == "DirectoryBoundary":
            continue
        end = size
        for next_start, _next_name in starts[index + 1 :]:
            if next_start > start:
                end = next_start
                break
        if end > start:
            spans.append((start, end, table_name))
    return spans


def script_record_anchor_info(data: bytes | bytearray, strings: list[str], base: int, size: int, rel: int) -> tuple[int, str] | None:
    candidates: list[tuple[int, str]] = []
    for probe_rel in range(max(0, rel - 0x1C), min(size - 4, rel + 0x20) + 1, 4):
        raw = u32(data, base + probe_rel)
        if 0 <= raw < len(strings) and strings[raw] and not strings[raw].startswith("."):
            candidates.append((abs(probe_rel - rel), probe_rel, strings[raw]))
    if not candidates:
        return None
    candidates.sort(key=lambda item: item[0])
    return candidates[0][1], clean_label(candidates[0][2])


def script_record_anchor(data: bytes | bytearray, strings: list[str], base: int, size: int, rel: int) -> str | None:
    anchor = script_record_anchor_info(data, strings, base, size, rel)
    return anchor[1] if anchor else None


def script_field_label(
    data: bytes | bytearray,
    strings: list[str],
    base: int,
    size: int,
    table_name: str,
    rel: int,
    anchor_rel: int,
    stem: str,
) -> tuple[str, str | None]:
    raw = u32(data, base + rel)
    delta = rel - anchor_rel
    prefix = f"{table_name}.{stem}"
    if delta == 0 and 0 <= raw < len(strings) and strings[raw] and not strings[raw].startswith("."):
        return f"{prefix}.Name", "string"
    slot = abs(delta) // 4
    if raw % 4 == 0 and 0 < raw < size:
        field = "LinkedNode" if raw <= rel else "ChildNode"
        return f"{prefix}.{field}{slot:02d}", "ref"
    if raw != 0 and 0 <= raw < len(strings) and strings[raw] and not strings[raw].startswith("."):
        return f"{prefix}.StringParam{slot:02d}", "string"
    if looks_like_float(data, base + rel):
        return f"{prefix}.FloatParam{slot:02d}", "f32"
    if looks_like_u8x4(raw):
        return f"{prefix}.OpcodeFlags{slot:02d}", "u8x4"
    if looks_like_u16x2(raw):
        return f"{prefix}.OpcodePair{slot:02d}", "u16x2"
    return f"{prefix}.IntParam{slot:02d}", None


def script_table_labels(
    data: bytes | bytearray,
    strings: list[str],
    base: int,
    size: int,
) -> tuple[dict[int, str], dict[int, str], dict[int, str]]:
    labels: dict[int, str] = {}
    forced_types: dict[int, str] = {}
    stems: dict[int, str] = {}
    for start, end, table_name in script_table_spans(data, base, size):
        current_stem = ""
        for rel in range(start, end, 4):
            anchor = script_record_anchor_info(data, strings, base, size, rel)
            if anchor:
                anchor_rel, current_stem = anchor
                stems.setdefault(anchor_rel, current_stem)
                labels[rel], force = script_field_label(data, strings, base, size, table_name, rel, anchor_rel, current_stem)
                if force:
                    forced_types[rel] = force
            else:
                labels[rel] = table_name
    return labels, forced_types, stems


def looks_like_collision_record(data: bytes | bytearray, base: int, size: int, rel: int) -> bool:
    if rel + 0x30 > size:
        return False
    floats = [f32(data, base + rel + i * 4) for i in range(5)]
    if not all(-10000.0 < value < 10000.0 for value in floats):
        return False
    if any(u32(data, base + rel + off) != 0 for off in (0x14, 0x18, 0x1C, 0x24, 0x28, 0x2C)):
        return False
    pair = u32(data, base + rel + 0x20)
    hi = (pair >> 16) & 0xFFFF
    lo = pair & 0xFFFF
    return hi < 0x200 and lo < 0x200 and pair != 0


def scan_collision_record_runs(data: bytes | bytearray, base: int, size: int) -> list[dict[str, int]]:
    runs: list[dict[str, int]] = []
    rel = 0
    while rel + 0x30 <= size:
        if not looks_like_collision_record(data, base, size, rel):
            rel += 4
            continue
        start = rel
        count = 0
        while looks_like_collision_record(data, base, size, rel):
            count += 1
            rel += 0x30
        if count >= 4:
            runs.append({"start": start, "count": count})
        else:
            rel = start + 4
    return runs


def collision_record_labels(
    data: bytes | bytearray,
    base: int,
    runs: list[dict[str, int]],
) -> tuple[dict[int, str], dict[int, str]]:
    labels: dict[int, str] = {}
    forced_types: dict[int, str] = {}
    fields = [
        (0x00, "float", "CenterX"),
        (0x04, "float", "CenterY"),
        (0x08, "float", "CenterZ"),
        (0x0C, "float", "RadiusOrExtentA"),
        (0x10, "float", "RadiusOrExtentB"),
        (0x14, "int", "Reserved14"),
        (0x18, "int", "Reserved18"),
        (0x1C, "int", "Reserved1C"),
        (0x20, "u16x2", "BoneOrChannelPair"),
        (0x24, "int", "Reserved24"),
        (0x28, "int", "Reserved28"),
        (0x2C, "int", "Reserved2C"),
    ]
    used_names: dict[str, int] = {}
    for _run_index, run in enumerate(runs):
        start = int(run["start"])
        count = int(run["count"])
        for record_index in range(count):
            rel = start + record_index * 0x30
            pair = u32(data, base + rel + 0x20)
            hi = (pair >> 16) & 0xFFFF
            lo = pair & 0xFFFF
            base_name = f"CollisionSphere.Bone{hi:03d}_Channel{lo:03d}"
            duplicate = used_names.get(base_name, 0)
            used_names[base_name] = duplicate + 1
            record_name = base_name if duplicate == 0 else f"{base_name}_Alt{duplicate:02d}"
            for field_rel, kind, field_name in fields:
                labels[rel + field_rel] = f"{record_name}.{field_name}"
                forced_types[rel + field_rel] = kind
    return labels, forced_types


def scan_string_triple_runs(data: bytes | bytearray, strings: list[str], base: int, size: int) -> list[dict[str, int]]:
    runs: list[dict[str, int]] = []
    rel = 0
    while rel + 0x0C <= size:
        count = 0
        while rel + (count + 1) * 0x0C <= size:
            ids = [u32(data, base + rel + count * 0x0C + field) for field in (0, 4, 8)]
            if not all(0 <= value < len(strings) and strings[value] for value in ids):
                break
            if any(strings[value].startswith(".") for value in ids):
                break
            # The middle string is usually the runtime class, and first/third are the instance name.
            if strings[ids[0]] != strings[ids[2]]:
                break
            count += 1
        if count >= 3:
            runs.append({"start": rel, "count": count})
            rel += count * 0x0C
        else:
            rel += 4
    return runs


def string_triple_labels(
    data: bytes | bytearray,
    strings: list[str],
    base: int,
    runs: list[dict[str, int]],
) -> tuple[dict[int, str], dict[int, str], dict[int, str]]:
    labels: dict[int, str] = {}
    forced_types: dict[int, str] = {}
    entry_stems: dict[int, str] = {}
    used_stems: dict[str, int] = {}
    for _run_index, run in enumerate(runs):
        start = int(run["start"])
        count = int(run["count"])
        for entry in range(count):
            rel = start + entry * 0x0C
            name = clean_label(strings[u32(data, base + rel)])
            cls = clean_label(strings[u32(data, base + rel + 0x04)])
            base_stem = f"{name}.{cls}"
            duplicate = used_stems.get(base_stem, 0)
            used_stems[base_stem] = duplicate + 1
            stem = base_stem if duplicate == 0 else f"{base_stem}.Alt{duplicate:02d}"
            labels[rel] = f"{stem}.Name"
            labels[rel + 0x04] = f"{stem}.Class"
            labels[rel + 0x08] = f"{stem}.Alias"
            forced_types[rel] = "string"
            forced_types[rel + 0x04] = "string"
            forced_types[rel + 0x08] = "string"
            entry_stems[rel] = stem
    return labels, forced_types, entry_stems


def scan_pointer_runs(data: bytes | bytearray, base: int, size: int) -> list[dict[str, int]]:
    runs: list[dict[str, int]] = []
    rel = 0x100
    while rel + 0x10 <= size:
        count = 0
        last = -1
        while rel + (count + 1) * 4 <= size:
            target = u32(data, base + rel + count * 4)
            if not (target % 4 == 0 and 0 < target < size):
                break
            # Most Character_Data pointer arrays are sorted lists into later records.
            if count and target < last:
                break
            last = target
            count += 1
        if count >= 4:
            runs.append({"start": rel, "count": count})
            rel += count * 4
        else:
            rel += 4
    return runs


def target_record_name(data: bytes | bytearray, strings: list[str], base: int, size: int, target: int) -> str | None:
    if not (0 <= target <= size - 4):
        return None
    if target in KNOWN_POINTER_DIRECTORIES:
        return KNOWN_POINTER_DIRECTORIES[target][0]
    candidates: list[tuple[int, str]] = []
    for field_rel in range(-0xC0, 0xA0, 0x04):
        probe = target + field_rel
        if probe < 0 or probe > size - 4:
            continue
        raw = u32(data, base + probe)
        if 0 <= raw < len(strings) and strings[raw] and not strings[raw].startswith("."):
            candidates.append((field_rel, strings[raw]))
    if not candidates:
        return None
    # Prefer the first field for action/state records, animation name at +0x0C for ChAnimResource.
    type_id = u32(data, base + target + 0x08) if target + 0x08 <= size - 4 else 0
    if 0 <= type_id < len(strings) and strings[type_id].startswith("ChAnim"):
        name_id = u32(data, base + target + 0x0C) if target + 0x0C <= size - 4 else len(strings)
        if 0 <= name_id < len(strings):
            return cstr_safe(strings[name_id])
    candidates.sort(key=lambda item: (item[0] > 0, abs(item[0])))
    for _field_rel, candidate in candidates:
        if clean_label(candidate) not in GENERIC_RECORD_NAMES:
            return cstr_safe(candidate)
    return cstr_safe(candidates[0][1])


def merge_known_stem(known_stems: dict[int, str], target: int, stem: str) -> None:
    existing = known_stems.get(target)
    if existing is None:
        known_stems[target] = stem
        return
    if existing in GENERIC_RECORD_NAMES and "." in stem:
        known_stems[target] = stem


def containing_known_stem(known_stems: dict[int, str], rel: int) -> tuple[int, str] | None:
    starts = [start for start in known_stems if start <= rel]
    if not starts:
        return None
    start = max(starts)
    if rel - start > 0x2000:
        return None
    return start, known_stems[start]


def pointer_run_context(start: int, known_stems: dict[int, str]) -> tuple[str, str]:
    if start in KNOWN_POINTER_DIRECTORIES:
        return KNOWN_POINTER_DIRECTORIES[start]
    owner = containing_known_stem(known_stems, start)
    if owner:
        _owner_start, owner_stem = owner
        return (owner_stem, owner_stem)
    return ("", "")


def pointer_run_labels(
    data: bytes | bytearray,
    strings: list[str],
    base: int,
    size: int,
    runs: list[dict[str, int]],
    known_stems: dict[int, str],
) -> tuple[dict[int, str], dict[int, str], dict[int, str]]:
    labels: dict[int, str] = {}
    forced_types: dict[int, str] = {}
    pointed_stems: dict[int, str] = {}
    for run_index, run in enumerate(runs):
        start = int(run["start"])
        count = int(run["count"])
        directory_name, record_prefix = pointer_run_context(start, known_stems)
        for entry in range(count):
            rel = start + entry * 4
            target = u32(data, base + rel)
            record_name = target_record_name(data, strings, base, size, target)
            target_stem = known_stems.get(target)
            target_owner = containing_known_stem(known_stems, target)
            if target_stem is None:
                if target_owner and target - target_owner[0] <= 0x400:
                    target_stem = target_owner[1]
                elif record_name:
                    target_stem = f"{record_prefix}.{clean_label(record_name)}" if record_prefix else clean_label(record_name)
                else:
                    target_stem = None
            if target_owner and target - target_owner[0] <= 0x400:
                entry_name = target_owner[1]
            else:
                entry_name = clean_label(record_name) if record_name else ""
            if directory_name and entry_name:
                labels[rel] = f"{directory_name}.{entry_name}"
            elif entry_name:
                labels[rel] = entry_name
            else:
                labels[rel] = directory_name or "UnidentifiedReference"
            controller_label = default_controller_pointer_label(labels[rel], entry)
            if controller_label:
                labels[rel] = controller_label
            forced_types[rel] = "ref"
            if target >= 0x100 and target_stem:
                pointed_stems.setdefault(target, target_stem)
    return labels, forced_types, pointed_stems


def chanim_event_record_suffix(data: bytes | bytearray, strings: list[str], base: int, size: int, rel: int, end: int) -> str:
    first_raw = u32(data, base + rel)
    first = clean_label(strings[first_raw]) if 0 <= first_raw < len(strings) and strings[first_raw] else "Event"
    parts = [first]
    if end - rel >= 0x20:
        locator_raw = u32(data, base + rel + 0x14)
        if 0 <= locator_raw < len(strings) and strings[locator_raw]:
            parts.append(clean_label(strings[locator_raw]))
    return ".".join(part for part in parts if part)


def chanim_event_table_labels(
    data: bytes | bytearray,
    strings: list[str],
    base: int,
    size: int,
    chanims: list[dict[str, object]],
    pointer_runs: list[dict[str, int]],
) -> tuple[dict[int, str], dict[int, str], dict[int, str], dict[int, str]]:
    labels: dict[int, str] = {}
    forced_types: dict[int, str] = {}
    stems: dict[int, str] = {}
    headers: dict[int, str] = {}
    ordered_chanims = sorted(
        (int(record["rel"]), clean_label(str(record["anim"])), str(record["name"]), str(record["anim"]))
        for record in chanims
    )
    for index, (record_rel, owner, display_name, anim_name) in enumerate(ordered_chanims):
        event_start = record_rel + CHANIM_RECORD_SIZE
        next_record = ordered_chanims[index + 1][0] if index + 1 < len(ordered_chanims) else size
        candidates: list[dict[str, object]] = []
        for run in pointer_runs:
            table_start = int(run["start"])
            count = int(run["count"])
            if not (event_start <= table_start < next_record and count > 0):
                continue
            targets = [u32(data, base + table_start + entry * 4) for entry in range(count)]
            if not all(target % 4 == 0 and event_start <= target < table_start for target in targets):
                continue
            if any(targets[i] > targets[i + 1] for i in range(len(targets) - 1)):
                continue
            if targets[0] != event_start:
                continue
            candidates.append({"start": table_start, "targets": targets})
        if not candidates:
            continue
        best = max(candidates, key=lambda item: len(item["targets"]))
        table_start = int(best["start"])
        targets = list(best["targets"])
        stems[table_start] = f"ChAnimEventDirectory.{owner}"
        headers[event_start] = f"## ChAnim Event Character_Data+0x{event_start:06X} {display_name} / {anim_name}"
        headers[table_start] = f"## ChAnim Event Directory Character_Data+0x{table_start:06X} {display_name} / {anim_name}"
        for event_index, target in enumerate(targets):
            end = targets[event_index + 1] if event_index + 1 < len(targets) else table_start
            if end <= target or end - target > 0x80:
                continue
            suffix = chanim_event_record_suffix(data, strings, base, size, target, end)
            stem = suffix
            internal_stem = f"ChAnimEvent.{owner}.{suffix}"
            stems[target] = internal_stem
            labels[table_start + event_index * 4] = suffix
            forced_types[table_start + event_index * 4] = "ref"
            labels[target] = f"{stem}.Name"
            forced_types[target] = "string"
            if target + 0x04 < end:
                labels[target + 0x04] = f"{stem}.Time"
                forced_types[target + 0x04] = "f32"
            if target + 0x08 < end:
                raw = u32(data, base + target + 0x08)
                if 0 <= raw < len(strings) and strings[raw]:
                    labels[target + 0x08] = f"{stem}.DataClass"
                    forced_types[target + 0x08] = "string"
                else:
                    labels[target + 0x08] = f"{stem}.EventTypeFlags"
                    forced_types[target + 0x08] = "u8x4"
            if target + 0x0C < end:
                raw = u32(data, base + target + 0x0C)
                if raw % 4 == 0 and target + 0x10 <= raw < end:
                    labels[target + 0x0C] = f"{stem}.DataRef"
                    forced_types[target + 0x0C] = "ref"
                    data_stem = f"{internal_stem}.HitData"
                    stems.setdefault(raw, data_stem)
                elif 0 <= raw < len(strings) and strings[raw]:
                    labels[target + 0x0C] = f"{stem}.ActionName"
                    forced_types[target + 0x0C] = "string"
                else:
                    field = "ParamValue" if looks_like_float(data, base + target + 0x0C) else "Param"
                    labels[target + 0x0C] = f"{stem}.{field}"
                    forced_types[target + 0x0C] = "f32" if field == "ParamValue" else "int"
            if end - target >= 0x20:
                hit_fields = [
                    (0x10, "string", "HitAction"),
                    (0x14, "string", "HitLocator"),
                    (0x18, "string", "HitReaction"),
                    (0x1C, "string", "HitSize"),
                ]
                for field_rel, kind, field_name in hit_fields:
                    labels[target + field_rel] = f"{stem}.{field_name}"
                    forced_types[target + field_rel] = kind
            for extra_rel in range(target, end, 4):
                if extra_rel in labels:
                    continue
                raw = u32(data, base + extra_rel)
                slot = (extra_rel - target) // 4
                if raw != 0 and 0 <= raw < len(strings) and strings[raw] and not strings[raw].startswith("."):
                    labels[extra_rel] = f"{stem}.StringParam{slot:02d}"
                    forced_types[extra_rel] = "string"
                elif looks_like_float(data, base + extra_rel):
                    labels[extra_rel] = f"{stem}.FloatParam{slot:02d}"
                    forced_types[extra_rel] = "f32"
                elif looks_like_u8x4(raw):
                    labels[extra_rel] = f"{stem}.OpcodeFlags{slot:02d}"
                    forced_types[extra_rel] = "u8x4"
                elif looks_like_u16x2(raw):
                    labels[extra_rel] = f"{stem}.OpcodePair{slot:02d}"
                    forced_types[extra_rel] = "u16x2"
                else:
                    labels[extra_rel] = f"{stem}.IntParam{slot:02d}"
    return labels, forced_types, stems, headers


def generic_value_field_name(data: bytes | bytearray, strings: list[str], absolute: int, raw: int, character_data_size: int) -> str:
    if raw != 0 and 0 <= raw < len(strings) and strings[raw]:
        return "String"
    if raw % 4 == 0 and 0x100 <= raw < character_data_size:
        return "Ref"
    exponent = (raw >> 23) & 0xFF
    value = f32(data, absolute)
    if raw != 0 and 0x70 <= exponent <= 0x8E and abs(value) < 1000000.0:
        return "Float"
    if looks_like_u16x2(raw):
        return "Pair"
    if looks_like_u8x4(raw):
        return "Bytes"
    return "Int"


def default_controller_local_stem(stem: str) -> str:
    if stem == DEFAULT_CONTROLLER_PREFIX:
        return "DefaultController"
    if stem.startswith(DEFAULT_CONTROLLER_PREFIX + "."):
        return "DefaultController." + stem[len(DEFAULT_CONTROLLER_PREFIX) + 1 :]
    return stem


def default_controller_field_name(
    data: bytes | bytearray,
    strings: list[str],
    base: int,
    size: int,
    rel: int,
    start: int,
    stem: str,
    generic_kind: str,
) -> str:
    local = default_controller_local_stem(stem)
    slot = (rel - start) // 4
    raw = u32(data, base + rel)
    if raw != 0 and 0 <= raw < len(strings) and strings[raw] and not strings[raw].startswith("."):
        return f"{local}.Name" if slot == 0 else f"{local}.StringParam{slot:02d}"
    if generic_kind == "Ref":
        ref_field = {
            0: "LinkedNode",
            2: "ActionRef",
            4: "ChildNode",
            8: "NodeListRef",
        }.get(slot, f"RefParam{slot:02d}")
        return f"{local}.{ref_field}"
    if generic_kind == "Float":
        float_field = {
            1: "StartTime",
            6: "PlaybackRate",
            7: "Duration",
        }.get(slot, f"FloatParam{slot:02d}")
        return f"{local}.{float_field}"
    if generic_kind == "Bytes":
        return f"{local}.TriggerFlags{slot:02d}"
    if generic_kind == "Pair":
        return f"{local}.InputPair{slot:02d}"
    int_field = {
        0: "Enabled",
        3: "ActionFamily",
        5: "Flags",
        7: "InputMask",
    }.get(slot, f"IntParam{slot:02d}")
    return f"{local}.{int_field}"


def default_controller_pointer_label(label: str, entry: int) -> str | None:
    local = default_controller_local_stem(label)
    if not local.startswith("DefaultController"):
        return None
    suffix = "NodeRef" if local == "DefaultController" else "LinkedNodeRef"
    return f"{local}.{suffix}{entry:02d}"


def generic_owned_range_labels(
    data: bytes | bytearray,
    strings: list[str],
    base: int,
    size: int,
    starts: dict[int, str],
    occupied: set[int],
) -> tuple[dict[int, str], dict[int, str]]:
    labels: dict[int, str] = {}
    forced_types: dict[int, str] = {}
    ordered = sorted((rel, stem) for rel, stem in starts.items() if 0 <= rel < size)
    if not ordered:
        return labels, forced_types
    for index, (start, stem) in enumerate(ordered):
        end = ordered[index + 1][0] if index + 1 < len(ordered) else size
        if end <= start or end - start > 0x8000:
            continue
        for rel in range(start, end, 4):
            if rel in occupied:
                continue
            raw = u32(data, base + rel)
            field_name = generic_value_field_name(data, strings, base + rel, raw, size)
            if field_name == "Ref":
                forced_types[rel] = "ref"
            elif field_name == "String":
                forced_types[rel] = "string"
            elif field_name == "Float":
                forced_types[rel] = "f32"
            elif field_name == "Pair":
                forced_types[rel] = "u16x2"
            elif field_name == "Bytes":
                forced_types[rel] = "u8x4"
            if stem == DEFAULT_CONTROLLER_PREFIX or stem.startswith(DEFAULT_CONTROLLER_PREFIX + "."):
                labels[rel] = default_controller_field_name(data, strings, base, size, rel, start, stem, field_name)
            else:
                labels[rel] = stem
    return labels, forced_types


def fallback_region_labels(size: int, occupied: set[int]) -> dict[int, str]:
    labels: dict[int, str] = {}
    region_index = 0
    rel = 0
    while rel < size:
        if rel in occupied:
            rel += 4
            continue
        start = rel
        while rel < size and rel not in occupied:
            rel += 4
        for off in range(start, rel, 4):
            labels[off] = f"UnclassifiedRegion{region_index:03d}.Value"
        region_index += 1
    return labels


def export_row_type_and_value(
    data: bytes | bytearray,
    strings: list[str],
    absolute_offset: int,
    force: str | None = None,
) -> tuple[str, str]:
    raw = u32(data, absolute_offset)
    if force == "string":
        return "string", string_value(data, strings, absolute_offset)
    if force == "f32":
        return "float", repr(float(f32(data, absolute_offset)))
    if force == "u16x2":
        return "u16x2", u16x2_text(raw)
    if force == "u8x4":
        return "u8x4", u8x4_text(raw)
    if force == "ref":
        return "ref", str(raw if raw < 0x80000000 else raw - 0x100000000)
    if force == "bool":
        return "bool", "true" if raw else "false"
    if force == "int":
        return "int", str(raw if raw < 0x80000000 else raw - 0x100000000)

    if raw != 0 and 0 <= raw < len(strings) and strings[raw]:
        return "string", string_value(data, strings, absolute_offset)

    if looks_like_u16x2(raw):
        return "u16x2", u16x2_text(raw)
    if looks_like_u8x4(raw):
        return "u8x4", u8x4_text(raw)

    # Prefer float display only for values that look like intentional scalars.
    value = f32(data, absolute_offset)
    exponent = (raw >> 23) & 0xFF
    if raw != 0 and 0x70 <= exponent <= 0x8E and abs(value) < 1000000.0:
        return "float", repr(float(value))

    return "int", str(raw if raw < 0x80000000 else raw - 0x100000000)


def ref_target_text(
    data: bytes | bytearray,
    strings: list[str],
    base: int,
    size: int,
    target: int,
    known_stems: dict[int, str],
) -> str:
    if target % 4 != 0 or not (0 <= target < size):
        return str(target if target < 0x80000000 else target - 0x100000000)
    if target < 0x1800:
        mask_owner_candidates = [
            (start, stem)
            for start, stem in known_stems.items()
            if 0 <= start < target and target - start <= 0xF4 and "ProjectileData" not in stem
        ]
        if mask_owner_candidates:
            _start, stem = max(mask_owner_candidates, key=lambda item: item[0])
            return f"{stem} # @0x{target:06X}"
    owner = containing_known_stem(known_stems, target)
    name = None
    if owner and target - owner[0] <= 0x400:
        name = owner[1]
    if not name:
        name = known_stems.get(target)
    if not name:
        record_name = target_record_name(data, strings, base, size, target)
        if record_name:
            name = clean_label(record_name)
    if name:
        return f"{name} # @0x{target:06X}"
    return f"@0x{target:06X}"


def short_chanim_ref_text(value_text: str) -> str:
    ref_comment = REF_COMMENT_RE.search(value_text)
    comment = f" # @0x{ref_comment.group(1).upper()}" if ref_comment else ""
    name = strip_inline_comment(value_text)
    if name.startswith("ChAnimEventDirectory."):
        parts = name.split(".")
        return f"{'.'.join(parts[2:]) if len(parts) > 2 else 'EventDirectory'}{comment}"
    if name.startswith("ChAnimEvent."):
        parts = name.split(".")
        if len(parts) > 2:
            return f"{'.'.join(parts[2:])}{comment}"
    return value_text


def short_default_controller_ref_text(value_text: str) -> str:
    ref_comment = REF_COMMENT_RE.search(value_text)
    comment = f" # @0x{ref_comment.group(1).upper()}" if ref_comment else ""
    name = strip_inline_comment(value_text)
    if name == DEFAULT_CONTROLLER_PREFIX:
        return f"DefaultController{comment}"
    if name.startswith(DEFAULT_CONTROLLER_PREFIX + "."):
        return f"DefaultController.{name[len(DEFAULT_CONTROLLER_PREFIX) + 1 :]}{comment}"
    return value_text


def display_row_label(label: str) -> str:
    if DEFAULT_CONTROLLER_PREFIX in label:
        label = label.replace(DEFAULT_CONTROLLER_PREFIX, "DefaultController")
        label = label.replace("DefaultController.DefaultController", "DefaultController")
    return label


def chunk_key(label: str) -> str:
    parts = label.split(".")
    if len(parts) >= 2 and parts[0] in {
        "ActionData",
        "ActionLink",
        "AnimationDirectory",
        "Component",
        "ComponentDirectory",
        "DataInstanceRegistry",
        "ReactionRoot",
        "ReactionRootDirectory",
        "ScriptThread",
        "ScriptThreadDirectory",
        "StateCondition",
        "StateConditionDirectory",
    }:
        return ".".join(parts[:2])
    return parts[0]


def display_name(stem: str) -> str:
    return stem.replace("_", " ")


def block_header_for_chunk(chunk: str) -> str:
    if chunk == "CharacterDataHeader":
        return "CharacterDataHeader"
    return display_name(chunk)


def string_at(data: bytes | bytearray, strings: list[str], absolute: int) -> str | None:
    raw = u32(data, absolute)
    if 0 <= raw < len(strings) and strings[raw] and not strings[raw].startswith("."):
        return strings[raw]
    return None


def directory_entry_name(
    data: bytes | bytearray,
    strings: list[str],
    base: int,
    size: int,
    directory_name: str,
    target: int,
) -> str | None:
    if not (0 <= target <= size - 4):
        return None
    if directory_name == "AnimationDirectory":
        name = string_at(data, strings, base + target + 0x0C)
    else:
        name = string_at(data, strings, base + target)
    if not name:
        name = target_record_name(data, strings, base, size, target)
    if not name:
        return None
    return display_name(clean_label(name))


def directory_toc_blocks(
    data: bytes | bytearray,
    strings: list[str],
    base: int,
    size: int,
    pointer_runs: list[dict[str, int]],
) -> list[str]:
    lines: list[str] = []
    for run in sorted(pointer_runs, key=lambda item: int(item["start"])):
        start = int(run["start"])
        if start not in KNOWN_POINTER_DIRECTORIES:
            continue
        directory_name, _record_prefix = KNOWN_POINTER_DIRECTORIES[start]
        entries: list[tuple[int, str]] = []
        for entry in range(int(run["count"])):
            rel = start + entry * 4
            target = u32(data, base + rel)
            name = directory_entry_name(data, strings, base, size, directory_name, target)
            if not name:
                continue
            entries.append((target, name))
        if not entries:
            continue
        lines.append(f"[RootTables.{directory_name}]")
        for target, name in entries:
            lines.append(f"@0x{target:06X} {name}")
        lines.append("")
    return lines


def root_toc_lines(
    data: bytes | bytearray,
    strings: list[str],
    base: int,
    size: int,
    pointer_runs: list[dict[str, int]],
    mask_groups: list[dict[str, object]],
    header_target_stems: dict[int, str],
    chanims: list[dict[str, object]],
) -> list[str]:
    roots: list[tuple[int, str]] = []
    for group in mask_groups:
        roots.append((int(group["rel"]), clean_label(str(group["name"]))))
    for directory_start, (directory_name, _record_prefix) in KNOWN_POINTER_DIRECTORIES.items():
        if 0 <= directory_start < size:
            roots.append((directory_start, directory_name))
    directory_starts = set(KNOWN_POINTER_DIRECTORIES)
    roots.extend(
        (rel, stem)
        for rel, stem in header_target_stems.items()
        if 0 <= rel < size and rel not in directory_starts
    )
    lines: list[str] = [
        "# Click on table names to view contents",
        "[RootTables.Character_Data]",
    ]
    seen_offsets: set[int] = set()
    for rel, stem in sorted(roots, key=lambda item: (item[0], item[1])):
        if rel in seen_offsets:
            continue
        seen_offsets.add(rel)
        lines.append(f"@0x{rel:06X} {display_name(stem)}")
    lines.append("")
    lines.extend(directory_toc_blocks(data, strings, base, size, pointer_runs))
    if chanims:
        lines.append("[RootTables.ChAnimResources]")
        for record in sorted(chanims, key=lambda item: int(item["rel"])):
            lines.append(f"@0x{int(record['rel']):06X} {record['name']} / {record['anim']}")
        lines.append("")
    return lines


def scan_chanims(data: bytes | bytearray, strings: list[str], base: int, size: int) -> list[dict[str, object]]:
    records: list[dict[str, object]] = []
    seen: set[int] = set()
    for rel in range(0, size - CHANIM_RECORD_SIZE + 1, 4):
        try:
            type_index = u32(data, base + rel + 0x08)
            name_index = u32(data, base + rel + 0x0C)
            anim_index = u32(data, base + rel + 0x30)
        except struct.error:
            continue
        if not (0 <= type_index < len(strings) and 0 <= name_index < len(strings) and 0 <= anim_index < len(strings)):
            continue
        if strings[type_index] != CHANIM_TYPE:
            continue
        if rel in seen:
            continue
        seen.add(rel)
        records.append(
            {
                "rel": rel,
                "name": cstr_safe(strings[name_index]),
                "anim": cstr_safe(strings[anim_index]),
            }
        )
    return records


def chanim_field_labels(records: list[dict[str, object]]) -> dict[int, str]:
    labels: dict[int, str] = {}
    for record in records:
        rel = int(record["rel"])
        stem = str(record["anim"])
        for field_rel, field in {**CHANIM_STRING_FIELDS, **CHANIM_U32_FIELDS, **CHANIM_F32_FIELDS, **CHANIM_REF_FIELDS}.items():
            labels[rel + field_rel] = f"{stem}.{field}"
    return labels


def export_txt(bundle_path: Path, out_path: Path) -> None:
    data, _parser, _entries, strings, character_data = parse_bundle(bundle_path)
    base, size = character_data_span(character_data)
    chanims = scan_chanims(data, strings, base, size)
    chanim_labels = chanim_field_labels(chanims)
    mask_groups = scan_mask_groups(data, strings, base, size)
    mask_labels, mask_forced_types, mask_covered_offsets = mask_group_labels(mask_groups)
    annotate_mask_group_directory(data, base, size, mask_groups, mask_labels, mask_forced_types)
    header_labels, header_forced_types, header_target_stems = top_level_labels(data, strings, base, size)
    script_labels, script_forced_types, script_stems = script_table_labels(data, strings, base, size)
    collision_runs = scan_collision_record_runs(data, base, size)
    collision_labels, collision_forced_types = collision_record_labels(data, base, collision_runs)
    triple_runs = scan_string_triple_runs(data, strings, base, size)
    triple_labels, triple_forced_types, triple_stems = string_triple_labels(data, strings, base, triple_runs)

    known_stems: dict[int, str] = {}
    for record in chanims:
        known_stems[int(record["rel"])] = clean_label(str(record["anim"]))
    for group in mask_groups:
        known_stems[int(group["rel"])] = clean_label(str(group["name"]))
    for _run_index, run in enumerate(collision_runs):
        start = int(run["start"])
        count = int(run["count"])
        for record_index in range(count):
            rel = start + record_index * 0x30
            label = collision_labels.get(rel)
            if label:
                known_stems[rel] = label.split(".", 1)[0]
    known_stems.update(triple_stems)
    known_stems.update(script_stems)
    known_stems.update(header_target_stems)

    pointer_runs = scan_pointer_runs(data, base, size)
    event_labels, event_forced_types, event_stems, event_headers = chanim_event_table_labels(
        data, strings, base, size, chanims, pointer_runs
    )
    known_stems.update(event_stems)
    pointer_labels: dict[int, str] = {}
    pointer_forced_types: dict[int, str] = {}
    for _pass_index in range(3):
        pointer_labels, pointer_forced_types, pointed_stems = pointer_run_labels(
            data, strings, base, size, pointer_runs, known_stems
        )
        before = dict(known_stems)
        for target, stem in pointed_stems.items():
            merge_known_stem(known_stems, target, stem)
        if known_stems == before:
            break

    occupied_offsets = (
        set(chanim_labels)
        | set(mask_labels)
        | set(header_labels)
        | set(script_labels)
        | set(collision_labels)
        | set(triple_labels)
        | set(event_labels)
        | set(pointer_labels)
    )
    generic_labels, generic_forced_types = generic_owned_range_labels(data, strings, base, size, known_stems, occupied_offsets)
    occupied_offsets |= set(generic_labels)
    fallback_labels = fallback_region_labels(size, occupied_offsets)

    toc_lines = root_toc_lines(data, strings, base, size, pointer_runs, mask_groups, header_target_stems, chanims)

    lines: list[str] = [
        "# Character_Data text export",
        f"# SourceBDG={bundle_path}",
        f"# CharacterData={character_data['name']}",
        f"# CharacterDataOffset=0x{base:X}",
        f"# CharacterDataSize=0x{size:X}",
        "# Format: @offset <type> <name> = <value>",
        "# Types: string, float, int, ref, bool, u16x2, u8x4. Existing old-style f:/s:/hex imports are still accepted.",
        "",
    ]
    lines.extend(toc_lines)
    lines.append("[Character_Data]")

    record_starts = {int(record["rel"]): record for record in chanims}
    previous_chunk = ""
    for rel in range(0, size - 3, 4):
        record = record_starts.get(rel)
        if record is not None:
            lines.append("")
            lines.append(f"## ChAnimResource Character_Data+0x{rel:06X} {record['name']} / {record['anim']}")
        elif rel in event_headers:
            if lines and lines[-1] != "":
                lines.append("")
            lines.append(event_headers[rel])
        absolute = base + rel
        label = (
            chanim_labels.get(rel)
            or mask_labels.get(rel)
            or header_labels.get(rel)
            or script_labels.get(rel)
            or collision_labels.get(rel)
            or triple_labels.get(rel)
            or event_labels.get(rel)
            or pointer_labels.get(rel)
            or generic_labels.get(rel)
            or fallback_labels.get(rel)
        )
        if label is None:
            label = f"UnclassifiedRegion.Fallback0x{rel:06X}"
        label = display_row_label(label)
        chunk = chunk_key(label)
        if previous_chunk and chunk != previous_chunk and (not lines or lines[-1] != ""):
            lines.append("")
        if record is None and rel not in event_headers and rel not in event_labels and chunk != previous_chunk:
            lines.append(f"## {block_header_for_chunk(chunk)}")
        previous_chunk = chunk
        field_rel = None
        record_rel = None
        for start in record_starts:
            if start <= rel < start + CHANIM_RECORD_SIZE:
                field_rel = rel - start
                record_rel = start
                break
        force = (
            mask_forced_types.get(rel)
            or header_forced_types.get(rel)
            or script_forced_types.get(rel)
            or collision_forced_types.get(rel)
            or triple_forced_types.get(rel)
            or event_forced_types.get(rel)
            or pointer_forced_types.get(rel)
            or generic_forced_types.get(rel)
        )
        if record_rel is not None:
            if field_rel in CHANIM_STRING_FIELDS:
                force = "string"
            elif field_rel in CHANIM_F32_FIELDS:
                force = "f32"
            elif field_rel in CHANIM_REF_FIELDS:
                force = "ref"
            elif field_rel in CHANIM_U32_FIELDS:
                force = "int"
        if force is None and rel in mask_covered_offsets:
            raw = u32(data, absolute)
            if looks_like_u16x2(raw):
                force = "u16x2"
            elif looks_like_u8x4(raw):
                force = "u8x4"
        row_type, value_text = export_row_type_and_value(data, strings, absolute, force)
        if row_type == "ref":
            raw_target = u32(data, absolute)
            value_text = ref_target_text(data, strings, base, size, raw_target, known_stems)
            if rel in event_labels or label.endswith(".EventDirectory"):
                value_text = short_chanim_ref_text(value_text)
            if label.startswith("DefaultController") or DEFAULT_CONTROLLER_PREFIX in value_text:
                value_text = short_default_controller_ref_text(value_text)
        lines.append(f"@0x{rel:06X} {row_type:<8} {label} = {value_text}")

    out_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"Wrote {out_path}")
    print(f"Exported {size // 4} aligned Character_Data words.")
    print(f"Annotated {len(chanims)} ChAnimResource records.")
    print(f"Annotated {len(mask_groups)} mask groups.")
    print(f"Annotated {len(collision_runs)} collision record runs.")
    print(f"Annotated {len(triple_runs)} data-instance registry runs.")
    print(f"Annotated {len(pointer_runs)} reference runs.")


def metadata_from_txt(txt_path: Path) -> dict[str, str]:
    meta: dict[str, str] = {}
    for line in txt_path.read_text(encoding="utf-8").splitlines():
        match = META_RE.match(line)
        if match:
            meta[match.group(1).strip()] = match.group(2).strip()
    return meta


def parse_string_value(value: str, strings: list[str]) -> int:
    value = value.strip()
    if value in strings:
        return strings.index(value)
    return int(value, 0)


def parse_u32_value(value: str) -> int:
    return int(value.strip(), 0) & 0xFFFFFFFF


def parse_new_value(kind: str, value: str, strings: list[str]) -> bytes:
    ref_comment = REF_COMMENT_RE.search(value)
    value = strip_inline_comment(value)
    if kind in {"word", "int", "ref"}:
        if kind == "ref" and ref_comment and not re.fullmatch(r"[-+]?0[xX][0-9A-Fa-f]+|[-+]?\d+", value.strip()):
            return (int(ref_comment.group(1), 16) & 0xFFFFFFFF).to_bytes(4, "big")
        if value.lower().startswith("f:"):
            return struct.pack(">f", float(value[2:].strip()))
        if value.lower().startswith("s:"):
            return parse_string_value(value[2:].strip(), strings).to_bytes(4, "big")
        return parse_u32_value(value).to_bytes(4, "big")
    if kind == "string":
        if value.lower().startswith("s:"):
            value = value[2:].strip()
        return parse_string_value(value, strings).to_bytes(4, "big")
    if kind == "u32":
        return parse_u32_value(value).to_bytes(4, "big")
    if kind == "bool":
        normalized = value.strip().lower()
        if normalized in {"true", "yes", "on", "1"}:
            return (1).to_bytes(4, "big")
        if normalized in {"false", "no", "off", "0"}:
            return (0).to_bytes(4, "big")
        raise ValueError(f"bool value must be true/false or 1/0: {value}")
    if kind == "f32":
        return struct.pack(">f", float(value.strip()))
    if kind == "float":
        raw = value[2:].strip() if value.lower().startswith("f:") else value.strip()
        return struct.pack(">f", float(raw))
    if kind == "u16x2":
        parts = [part.strip() for part in value.split(",")]
        if len(parts) != 2:
            raise ValueError(f"u16x2 needs two comma-separated values: {value}")
        hi, lo = (int(part, 0) & 0xFFFF for part in parts)
        return ((hi << 16) | lo).to_bytes(4, "big")
    if kind == "u8x4":
        parts = [part.strip() for part in value.split(",")]
        if len(parts) != 4:
            raise ValueError(f"u8x4 needs four comma-separated values: {value}")
        raw = 0
        for part in parts:
            raw = (raw << 8) | (int(part, 0) & 0xFF)
        return raw.to_bytes(4, "big")
    raise ValueError(f"Unsupported row kind {kind}")


def rebuild_zip_for_bdg(bundle_path: Path, payload: bytes) -> bool:
    zip_path = bundle_path.with_suffix(".zip")
    if not zip_path.exists():
        return False

    with zipfile.ZipFile(zip_path, "r") as old_zip:
        infos = old_zip.infolist()
        existing = {info.filename: old_zip.read(info.filename) for info in infos}

    replaced = False
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as new_zip:
        for info in infos:
            is_target = Path(info.filename).name.lower() == bundle_path.name.lower()
            zi = zipfile.ZipInfo(info.filename, date_time=info.date_time)
            zi.external_attr = info.external_attr
            zi.comment = info.comment
            zi.compress_type = zipfile.ZIP_DEFLATED
            new_zip.writestr(zi, payload if is_target else existing[info.filename])
            replaced = replaced or is_target
        if not replaced:
            new_zip.writestr(bundle_path.name, payload)
            replaced = True

    with zipfile.ZipFile(zip_path, "r") as check_zip:
        bad = check_zip.testzip()
        if bad:
            raise RuntimeError(f"bad member in rebuilt {zip_path}: {bad}")
    return replaced


def import_txt(txt_path: Path, bundle_override: Path | None = None, dry_run: bool = False) -> None:
    meta = metadata_from_txt(txt_path)
    bundle_path = bundle_override
    if bundle_path is None:
        raw_source = meta.get("SourceBDG")
        bundle_path = Path(raw_source) if raw_source else None
    if bundle_path is None or not bundle_path.exists():
        bundle_path = pick_open_file(
            "Select BDG bundle to update",
            [("BDG bundles", "*.bdg *.BDG"), ("All files", "*.*")],
            GAME_DIR,
        )
    bundle_path = (ROOT / bundle_path).resolve() if not bundle_path.is_absolute() else bundle_path.resolve()

    data, _parser, _entries, strings, character_data = parse_bundle(bundle_path)
    base, size = character_data_span(character_data)
    changes: list[dict[str, object]] = []
    wanted: dict[int, tuple[str, bytes, str, str]] = {}
    conflicts: list[str] = []

    for line in txt_path.read_text(encoding="utf-8").splitlines():
        match = ROW_RE.match(line.strip())
        if not match:
            continue
        rel = int(match.group(1), 16)
        kind = match.group(2)
        label = match.group(3).strip()
        value_text = match.group(4).strip()
        if kind not in {"string", "u32", "f32", "float", "int", "word", "ref", "bool", "u16x2", "u8x4"}:
            continue
        if rel < 0 or rel + 4 > size or rel % 4:
            continue
        absolute = base + rel
        old_bytes = bytes(data[absolute : absolute + 4])
        clean_value = strip_inline_comment(value_text)
        if kind == "string":
            compare_value = clean_value[2:].strip() if clean_value.lower().startswith("s:") else clean_value
            if compare_value == string_value(data, strings, absolute):
                continue
        new_bytes = parse_new_value(kind, value_text, strings)
        if old_bytes == new_bytes:
            continue
        previous = wanted.get(rel)
        if previous and previous[1] != new_bytes:
            conflicts.append(f"@0x{rel:06X} has conflicting edits: {previous[2]} vs {value_text}")
            continue
        wanted[rel] = (kind, new_bytes, value_text, label)

    if conflicts:
        raise RuntimeError("Conflicting duplicate-offset edits:\n  " + "\n  ".join(conflicts))

    for rel, (kind, new_bytes, value_text, label) in sorted(wanted.items()):
        absolute = base + rel
        old_text = row_value(data, strings, absolute, kind)
        data[absolute : absolute + 4] = new_bytes
        new_text = row_value(data, strings, absolute, kind)
        changes.append(
            {
                "offset": f"Character_Data+0x{rel:06X}",
                "type": kind,
                "label": label,
                "old": old_text,
                "new": new_text,
                "requested": value_text,
            }
        )

    if not changes:
        print("No changed editable Character_Data values found.")
        return

    print(f"{'Would apply' if dry_run else 'Applying'} {len(changes)} Character_Data changes to {bundle_path}:")
    for change in changes[:60]:
        print(f"  {change['offset']} {change['label']}: {change['old']} -> {change['new']}")
    if len(changes) > 60:
        print(f"  ... {len(changes) - 60} more")

    if dry_run:
        return

    backup_dir = BACKUP_ROOT / f"character_data_txt_import_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    bdg_backup = backup_dir / bundle_path.relative_to(ROOT)
    bdg_backup.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(bundle_path, bdg_backup)
    zip_path = bundle_path.with_suffix(".zip")
    if zip_path.exists():
        zip_backup = backup_dir / zip_path.relative_to(ROOT)
        zip_backup.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(zip_path, zip_backup)

    bundle_path.write_bytes(data)
    zip_rebuilt = rebuild_zip_for_bdg(bundle_path, bytes(data))
    print(f"Backup: {backup_dir}")
    print(f"Rebuilt zip: {zip_rebuilt}")


def interactive_main() -> int:
    print("Character_Data TXT Tool")
    print("1. Export Character_Data to txt")
    print("2. Import txt back into Character_Data")
    choice = ask("Choose mode", "1")
    if choice == "1":
        bundle_path = pick_open_file(
            "Select character BDG bundle",
            [("BDG bundles", "*.bdg *.BDG"), ("All files", "*.*")],
            GAME_DIR,
        )
        out_path = pick_save_file(
            "Save Character_Data txt",
            f"{bundle_path.stem}_Character_Data.txt",
            [("Text files", "*.txt"), ("All files", "*.*")],
        )
        export_txt(bundle_path, out_path)
    elif choice == "2":
        txt_path = pick_open_file(
            "Select edited Character_Data txt",
            [("Text files", "*.txt"), ("All files", "*.*")],
            ROOT,
        )
        import_txt(txt_path)
    else:
        raise ValueError("Choose 1 or 2")
    return 0


def cli_main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Export/import editable Character_Data ChAnimResource rows.")
    sub = parser.add_subparsers(dest="cmd")

    export_p = sub.add_parser("export", help="Export a character BDG's Character_Data to txt.")
    export_p.add_argument("bdg", type=Path)
    export_p.add_argument("--out", type=Path)

    import_p = sub.add_parser("import", help="Import edited Character_Data txt into its source BDG.")
    import_p.add_argument("txt", type=Path)
    import_p.add_argument("--bdg", type=Path, help="Override SourceBDG from the txt.")
    import_p.add_argument("--dry-run", action="store_true")

    args = parser.parse_args(argv)
    if args.cmd is None:
        return interactive_main()
    if args.cmd == "export":
        out = args.out or Path(f"{args.bdg.stem}_Character_Data.txt")
        export_txt(args.bdg, out)
        return 0
    if args.cmd == "import":
        import_txt(args.txt, args.bdg, args.dry_run)
        return 0
    parser.error("unknown command")
    return 2


def main() -> int:
    return cli_main(sys.argv[1:])


if __name__ == "__main__":
    raise SystemExit(main())
