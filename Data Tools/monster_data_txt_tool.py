#!/usr/bin/env python3
from __future__ import annotations

import argparse
import math
import re
import shutil
import struct
import sys
import zipfile
from datetime import datetime
from pathlib import Path
from tkinter import Tk, filedialog


def app_dir() -> Path:
    module_dir = Path(__file__).resolve().parent
    if module_dir.exists():
        return module_dir
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return module_dir


TOOL_DIR = app_dir()
ROOT = TOOL_DIR.parent
BACKUP_ROOT = ROOT / "backups"
GAME_DIR = ROOT / "DATA" / "files" / "Game"

ROW_RE = re.compile(r"^@0x([0-9A-Fa-f]+)\s+([a-zA-Z0-9_]+(?:\[[0-9A-Fa-fxX]+\])?)\s+(.+?)\s+=\s+(.*)$")
NAMED_ROW_RE = re.compile(r"^(.+?)\s*=\s*(.*?)\s+#\s*@0x([0-9A-Fa-f]+)(?:\s+([a-zA-Z0-9_]+))?\b")
META_RE = re.compile(r"^#\s*([^=]+?)=(.*)$")

CHANIM_TYPE = "ChAnimResource"
CHANIM_RECORD_SIZE = 0x64

CHANIM_STRING_FIELDS = {
    0x08: "Type",
    0x0C: "ResourceName",
    0x30: "Animation",
}

CHANIM_F32_FIELDS = {
    0x44: "Speed",
}

CHANIM_U32_FIELDS = {
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
    0x40: "StartEvent",
    0x48: "SpeedFlags",
    0x4C: "EndEvent",
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

PLACEHOLDER_STRINGS = {"", "000"}


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
    return struct.unpack_from("<I", data, offset)[0]


def put_u32(data: bytearray, offset: int, value: int) -> None:
    struct.pack_into("<I", data, offset, value & 0xFFFFFFFF)


def f32(data: bytes | bytearray, offset: int) -> float:
    return struct.unpack_from("<f", data, offset)[0]


def put_f32(data: bytearray, offset: int, value: float) -> None:
    struct.pack_into("<f", data, offset, float(value))


def parse_bundle(bundle_path: Path):
    data = bytearray(bundle_path.read_bytes())
    parser = PipeworksParser(bundle_path)
    entries = parser.parse_from_data(bytes(data))
    strings = parser.read_strings()
    character_data = next((entry for entry in entries if entry["name"] == "2/000MONSTER_DATA"), None)
    if character_data is None:
        raise RuntimeError(f"{bundle_path} has no 2/000MONSTER_DATA entry")
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
    if kind in {"u32", "word", "int", "ref"}:
        return f"0x{u32(data, absolute_offset):08X}"
    if kind == "bool":
        return "true" if u32(data, absolute_offset) else "false"
    if kind == "u16x2":
        return u16x2_text(u32(data, absolute_offset))
    if kind == "u8x4":
        return u8x4_text(u32(data, absolute_offset))
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
    return f"{raw & 0xFFFF}, {(raw >> 16) & 0xFFFF}"


def u8x4_text(raw: int) -> str:
    return ", ".join(str((raw >> shift) & 0xFF) for shift in (24, 16, 8, 0))


def looks_like_u16x2(raw: int) -> bool:
    hi = (raw >> 16) & 0xFFFF
    lo = raw & 0xFFFF
    return hi <= 0x0100 and lo <= 0x0100 and (hi != 0 or lo != 0) and lo in {hi + 1, 0, 0xFFFF}


def looks_like_small_u16x2(raw: int) -> bool:
    hi = (raw >> 16) & 0xFFFF
    lo = raw & 0xFFFF
    return hi <= 0x0100 and lo <= 0x0100 and (hi != 0 or lo != 0)


def looks_like_u8x4(raw: int) -> bool:
    vals = [(raw >> shift) & 0xFF for shift in (24, 16, 8, 0)]
    return len(set(vals)) <= 3 and all(v in {0, 1, 2, 3, 6, 9, 15, 0xFF} for v in vals) and any(v not in {0, 0xFF} for v in vals)


def clean_label(value: str) -> str:
    value = cstr_safe(value).replace("/", "_").replace("\\", "_")
    return re.sub(r"\s+", "_", value)


def is_meaningful_string(value: str) -> bool:
    return cstr_safe(value) not in PLACEHOLDER_STRINGS


def string_id_at(data: bytes | bytearray, strings: list[str], absolute: int) -> int | None:
    raw = u32(data, absolute)
    if 0 <= raw < len(strings) and is_meaningful_string(strings[raw]):
        return raw
    return None


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


def script_record_anchor(data: bytes | bytearray, strings: list[str], base: int, size: int, rel: int) -> str | None:
    candidates: list[tuple[int, str]] = []
    for probe_rel in range(max(0, rel - 0x1C), min(size - 4, rel + 0x20) + 1, 4):
        raw = u32(data, base + probe_rel)
        if 0 <= raw < len(strings) and strings[raw] and not strings[raw].startswith("."):
            candidates.append((abs(probe_rel - rel), strings[raw]))
    if not candidates:
        return None
    candidates.sort(key=lambda item: item[0])
    return clean_label(candidates[0][1])


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
            anchor = script_record_anchor(data, strings, base, size, rel)
            if anchor:
                current_stem = anchor
                stems.setdefault(rel, current_stem)
            labels[rel] = current_stem or table_name
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
            bone_id = pair & 0xFFFF
            channel_id = (pair >> 16) & 0xFFFF
            base_name = f"CollisionSphere.Bone{bone_id:03d}_Channel{channel_id:03d}"
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
            # The middle string is usually the runtime class, and first/third are the instance name.
            if strings[ids[0]] != strings[ids[2]]:
                break
            if not is_meaningful_string(strings[ids[0]]) or not is_meaningful_string(strings[ids[1]]):
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


def scan_string_index_runs(data: bytes | bytearray, strings: list[str], base: int, size: int) -> list[dict[str, int]]:
    runs: list[dict[str, int]] = []
    rel = 0
    while rel + 0x10 <= size:
        count = 0
        meaningful = 0
        while rel + (count + 1) * 4 <= size:
            string_id = string_id_at(data, strings, base + rel + count * 4)
            if string_id is None:
                break
            meaningful += 1
            count += 1
        if count >= 4 and meaningful >= 4:
            runs.append({"start": rel, "count": count})
            rel += count * 4
        else:
            rel += 4
    return runs


def string_index_run_labels(
    data: bytes | bytearray,
    strings: list[str],
    base: int,
    runs: list[dict[str, int]],
    occupied: set[int] | None = None,
) -> tuple[dict[int, str], dict[int, str], dict[int, str]]:
    labels: dict[int, str] = {}
    forced_types: dict[int, str] = {}
    stems: dict[int, str] = {}
    occupied = occupied or set()
    for run_index, run in enumerate(runs):
        start = int(run["start"])
        stem = f"StringList{run_index:03d}"
        first_id = string_id_at(data, strings, base + start)
        if first_id is not None:
            first_name = clean_label(strings[first_id])
            if first_name:
                stem = f"{stem}_{first_name}"
        stems[start] = stem
        for entry in range(int(run["count"])):
            rel = start + entry * 4
            if rel in occupied:
                continue
            string_id = string_id_at(data, strings, base + rel)
            if string_id is None:
                continue
            labels[rel] = f"{stem}.Entry{entry:03d}"
            forced_types[rel] = "string"
    return labels, forced_types, stems


def zero_run_labels(
    data: bytes | bytearray,
    base: int,
    size: int,
    occupied: set[int],
) -> tuple[dict[int, str], dict[int, str]]:
    labels: dict[int, str] = {}
    forced_types: dict[int, str] = {}
    rel = 0
    run_index = 0
    while rel + 0x10 <= size:
        if rel in occupied or u32(data, base + rel) != 0:
            rel += 4
            continue
        start = rel
        count = 0
        while rel + 4 <= size and rel not in occupied and u32(data, base + rel) == 0:
            count += 1
            rel += 4
        if count >= 4:
            stem = f"ZeroPadding{run_index:03d}"
            for idx in range(count):
                off = start + idx * 4
                labels[off] = f"{stem}.Value"
                forced_types[off] = "int"
            run_index += 1
    return labels, forced_types


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
            # Most monster data pointer arrays are sorted lists into later records.
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
        if 0 <= raw < len(strings) and is_meaningful_string(strings[raw]) and not strings[raw].startswith("."):
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
            if directory_name == "BodyPartActionLookup":
                record_name = ""
                target_stem = None
                target_owner = None
            if target_owner and target_owner[1].startswith("ActionInput.") and target != target_owner[0]:
                target_owner = None
            if directory_name == "BodyPartActionLookup":
                if target_stem and target_stem.startswith("ActionInput."):
                    target_stem = None
                if target_owner and target_owner[1].startswith("ActionInput."):
                    target_owner = None
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
            if directory_name == "BodyPartActionLookup" and entry_name.startswith("ActionInput."):
                entry_name = ""
            if entry_name.lower().startswith("ref0x") and target_stem:
                entry_name = clean_label(target_stem)
            if directory_name and entry_name:
                labels[rel] = f"{directory_name}.{entry_name}"
            elif entry_name:
                labels[rel] = entry_name
            else:
                labels[rel] = directory_name or "UnidentifiedReference"
            forced_types[rel] = "ref"
            if target >= 0x100 and target_stem and directory_name != "BodyPartActionLookup":
                pointed_stems.setdefault(target, target_stem)
    return labels, forced_types, pointed_stems


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
    effect_start = u32(data, base + 0x0B50) if 0x0B54 <= size else 0
    effect_count = u32(data, base + 0x0B54) if 0x0B58 <= size else 0
    effect_end = effect_start + effect_count * 0x68 if effect_start and 0 < effect_count < 0x10000 else 0
    for index, (start, stem) in enumerate(ordered):
        end = ordered[index + 1][0] if index + 1 < len(ordered) else size
        if clean_label(stem).lower().startswith("effecttable"):
            if not (effect_start <= start < effect_end <= size):
                continue
            end = min(end, effect_end)
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


def ref_value_text(
    raw: int,
    size: int,
    labels: dict[int, str],
    roots: dict[int, str],
    known_stems: dict[int, str],
) -> str:
    if raw % 4 != 0 or not (0 < raw < size):
        return str(raw if raw < 0x80000000 else raw - 0x100000000)
    target_name = roots.get(raw) or known_stems.get(raw) or labels.get(raw)
    if not target_name:
        owners = [(off, stem) for off, stem in {**roots, **known_stems}.items() if off <= raw]
        if owners:
            owner_start, owner_stem = max(owners, key=lambda item: item[0])
            if raw - owner_start <= 0x100:
                target_name = owner_stem
    if not target_name:
        return str(raw if raw < 0x80000000 else raw - 0x100000000)
    return display_name(target_name)


def ref_lookup_key(value: str) -> str:
    return clean_label(value.strip()).lower()


def build_ref_name_lookup_from_text(text: str) -> dict[str, int]:
    lookup: dict[str, int] = {}
    for line in text.splitlines():
        stripped = line.strip()
        match = ROW_RE.match(stripped)
        if match:
            rel = int(match.group(1), 16)
            label = match.group(3).strip()
            for name in (label, display_name(label)):
                lookup.setdefault(ref_lookup_key(name), rel)
            continue
        toc_match = re.match(r"^@0x([0-9A-Fa-f]+)\s+(.+?)\s*$", stripped)
        if toc_match:
            rel = int(toc_match.group(1), 16)
            name = toc_match.group(2).strip()
            lookup.setdefault(ref_lookup_key(name), rel)
    return lookup


def augment_ref_lookup_with_current_refs(
    text: str,
    data: bytes | bytearray,
    base: int,
    size: int,
    lookup: dict[str, int],
) -> dict[str, int]:
    for line in text.splitlines():
        match = ROW_RE.match(line.strip())
        if not match:
            continue
        rel = int(match.group(1), 16)
        kind = match.group(2)
        value_text = strip_inline_comment(match.group(4)).strip()
        if kind != "ref" or not value_text or rel < 0 or rel + 4 > size:
            continue
        raw = u32(data, base + rel)
        if raw % 4 == 0 and 0 < raw < size:
            lookup.setdefault(ref_lookup_key(value_text), raw)
    return lookup


def ref_value_name_counts_from_text(text: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for line in text.splitlines():
        match = ROW_RE.match(line.strip())
        if not match or match.group(2) != "ref":
            continue
        value_text = strip_inline_comment(match.group(4)).strip()
        if not value_text:
            continue
        try:
            parse_u32_value(value_text)
            continue
        except ValueError:
            pass
        key = ref_lookup_key(value_text)
        counts[key] = counts.get(key, 0) + 1
    return counts


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
    for run_index, run in enumerate(sorted(pointer_runs, key=lambda item: int(item["start"]))):
        start = int(run["start"])
        directory_name = f"PointerDirectory{run_index:03d}"
        if start in KNOWN_POINTER_DIRECTORIES:
            directory_name, _record_prefix = KNOWN_POINTER_DIRECTORIES[start]
        entries: list[tuple[int, str]] = []
        for entry in range(int(run["count"])):
            rel = start + entry * 4
            target = u32(data, base + rel)
            name = directory_entry_name(data, strings, base, size, directory_name, target)
            if not name:
                name = f"Target0x{target:06X}"
            if not name:
                continue
            entries.append((target, name))
        if not entries:
            continue
        lines.append(f"[{directory_name}]")
        for target, name in entries:
            lines.append(f"0x{target:06X} {name}")
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
    extra_roots: dict[int, str] | None = None,
) -> list[str]:
    roots: list[tuple[int, str]] = []
    for group in mask_groups:
        roots.append((int(group["rel"]), clean_label(str(group["name"]))))
    for run_index, run in enumerate(pointer_runs):
        start = int(run["start"])
        directory_name = f"PointerDirectory{run_index:03d}"
        if start in KNOWN_POINTER_DIRECTORIES:
            directory_name = KNOWN_POINTER_DIRECTORIES[start][0]
        roots.append((start, directory_name))
    directory_starts = set(KNOWN_POINTER_DIRECTORIES)
    roots.extend(
        (rel, stem)
        for rel, stem in header_target_stems.items()
        if 0 <= rel < size and rel not in directory_starts
    )
    if extra_roots:
        roots.extend((rel, stem) for rel, stem in extra_roots.items() if 0 <= rel < size)
    lines: list[str] = ["[Roots]"]
    seen_offsets: set[int] = set()
    for rel, stem in sorted(roots, key=lambda item: (item[0], item[1])):
        if rel in seen_offsets:
            continue
        seen_offsets.add(rel)
        lines.append(f"0x{rel:06X} {display_name(stem)}")
    lines.append("")
    lines.extend(directory_toc_blocks(data, strings, base, size, pointer_runs))
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
        for field_rel, field in {**CHANIM_STRING_FIELDS, **CHANIM_U32_FIELDS, **CHANIM_F32_FIELDS}.items():
            labels[rel + field_rel] = f"{stem}.{field}"
    return labels


PS2_FIXED_ASCII_FIELDS = [
    (0x290, 0x100, "CueNames.FootstepLight"),
    (0x390, 0x100, "CueNames.FootstepMedium"),
    (0x490, 0x100, "CueNames.FootstepHeavy"),
    (0x590, 0x100, "CueNames.WaterFootstepLight"),
    (0x690, 0x100, "CueNames.WaterFootstepMedium"),
    (0x790, 0x100, "CueNames.WaterFootstepHeavy"),
    (0x890, 0x100, "CueNames.WinMove"),
    (0x990, 0x100, "CueNames.IntroMove"),
]

PS2_CORE_TUNING_RELS = tuple(range(0x1AC, 0x290, 4))

PS2_CORE_TUNING_FIELD_NAMES = {
    0x01AC: "Movement.MaxWalkSpeed",
    0x01B0: "Movement.MaxRunSpeed",
    0x01B4: "Movement.MaxChargeSpeed",
    0x01B8: "Movement.TurnAcceleration",
    0x01C8: "Scale.BodyX",
    0x01CC: "Scale.BodyY",
    0x01D0: "Scale.BodyZ",
    0x01D4: "Scale.Head",
    0x01D8: "Scale.Arms",
    0x01DC: "Scale.Legs",
    0x01E0: "Scale.Tail",
    0x01E4: "Scale.Weapon",
    0x01E8: "Scale.Effect",
    0x01EC: "Scale.Camera",
    0x01F0: "Scale.Grab",
    0x01F4: "Scale.Throw",
    0x0208: "Combat.LightHitReactionScale",
    0x020C: "Combat.HeavyHitReactionScale",
    0x0210: "Combat.MaxHitPoints",
    0x0214: "Combat.StartingHitPoints",
    0x022C: "Combat.EnergyRegenRate",
    0x0230: "Combat.EnergyCostScale",
    0x0234: "Combat.RageGainScale",
    0x0238: "Targeting.CloseRange",
    0x023C: "Targeting.MeleeRange",
    0x0240: "Targeting.MaxLockRange",
    0x0244: "Targeting.ThrowRange",
    0x0248: "Targeting.ProjectileRange",
    0x0250: "Collision.BodyRadius",
    0x0254: "Collision.BodyHeight",
    0x025C: "Collision.GrabRadius",
    0x0260: "Collision.ThrowRadius",
    0x0264: "Collision.AttackRadius",
    0x026C: "Collision.PickupRadius",
    0x0270: "Physics.Mass",
    0x0274: "Physics.PushStrength",
    0x0278: "Physics.KnockbackStrength",
    0x027C: "Physics.GroundFriction",
    0x0280: "Physics.AirControl",
    0x0284: "Physics.JumpStrength",
    0x0288: "Camera.Distance",
    0x028C: "Camera.Height",
}

PS2_STARTUP_TABLE_FIELD_NAMES = {
    0x0A94: "DefaultAction.Invalid",
    0x0A98: "DefaultAction.Attacks",
    0x0A9C: "DefaultAction.Punch",
    0x0AA0: "DefaultAction.Tail",
    0x0AA4: "DefaultAction.Bite",
    0x0AA8: "DefaultAction.AirInvalid",
    0x0AAC: "DefaultAction.AirSpin",
    0x0AB4: "ImpactSound.BluntFleshLight",
    0x0AB8: "ImpactSound.BluntFleshMedium",
    0x0ABC: "ImpactSound.BluntFleshHeavy",
    0x0AC0: "ImpactSound.BluntBoneBlocked",
    0x0AC4: "ImpactSound.EdgedFleshLight",
    0x0AC8: "ImpactSound.EdgedFleshMedium",
    0x0ACC: "ImpactSound.EdgedFleshHeavy",
    0x0AD0: "ImpactSound.BlockedPrimary",
    0x0AD4: "ImpactSound.BlockedSecondary",
    0x0AD8: "MoveBlend.ForwardX",
    0x0ADC: "MoveBlend.ForwardZ",
    0x0AE0: "MoveBlend.MinWeight",
    0x0AE4: "MoveBlend.MaxWeight",
    0x0AE8: "MoveBlend.FrameTime",
    0x0AEC: "MoveBlend.MaxTurnRadians",
    0x0AF0: "MoveBlend.HighTurnRadians",
    0x0AF4: "MoveBlend.LowTurnRadians",
    0x0AF8: "DefaultAction.AttacksFallback",
    0x0B18: "Camera.MinBlend",
    0x0B1C: "Camera.MaxBlend",
    0x0B3C: "IntroCamera.Invalid",
    0x0B40: "IntroCamera.Voice",
    0x0B54: "StartupAction.JumpUp",
    0x0B68: "StartupAction.Roar",
    0x0B74: "StartupAction.Punch",
    0x0B7C: "StartupAction.AirSpinUpB",
    0x0B88: "StartupAction.AirborneFacedown",
}

PS2_ACTION_RECORD_FIELD_NAMES = {
    0x00: "AnimRate",
    0x04: "MoveClass",
    0x08: "InputClass",
    0x0C: "ReactionLevel",
    0x10: "DamageScale",
    0x14: "HitStopScale",
    0x18: "HitDirectionX",
    0x1C: "HitDirectionZ",
    0x20: "FacingDirectionX",
    0x24: "FacingDirectionZ",
    0x28: "HitEventFlags",
    0x2C: "HitBehaviorFlags",
    0x30: "PrimaryDataRef",
    0x34: "ActionIndex",
    0x40: "StartFrame",
    0x44: "ActiveFrame",
    0x48: "RecoveryFrame",
    0x4C: "CancelWindow",
    0x50: "Priority",
    0x54: "RootMotionX",
    0x58: "RootMotionZ",
    0x5C: "RootMotionY",
    0x60: "InputWindowFlags",
    0x64: "InputWindowStart",
    0x68: "InputWindowEnd",
}

PS2_ACTION_RECORD_FIELD_TYPES = {
    0x00: "f32",
    0x04: "f32",
    0x08: "f32",
    0x0C: "f32",
    0x10: "f32",
    0x14: "f32",
    0x18: "f32",
    0x1C: "f32",
    0x20: "f32",
    0x24: "f32",
    0x28: "u16x2",
    0x2C: "u8x4",
    0x30: "ref",
    0x34: "int",
    0x40: "f32",
    0x44: "f32",
    0x48: "f32",
    0x4C: "f32",
    0x50: "f32",
    0x54: "f32",
    0x58: "f32",
    0x5C: "f32",
    0x60: "u8x4",
    0x64: "int",
    0x68: "ref",
}


PS2_INPUT_CODE_NAMES = {
    0x0A: "R2_RightTrigger",
    0x0B: "L2_LeftTrigger",
    0x0C: "R1_RightBumper",
    0x0D: "L1_LeftBumper",
    0x0E: "X_A_3",
    0x0F: "Circle_B_4",
    0x10: "Square_X_1",
    0x11: "Triangle_Y_2",
    0x14: "R3_RightStickClick",
    0x15: "L3_LeftStickClick",
    0x20: "WorldRight",
    0x21: "WorldUp",
    0x22: "WorldDown",
    0x23: "WorldLeft",
    0x3B: "RelativeUp",
    0x3C: "RelativeDown",
    0x3D: "RelativeBack",
    0x40: "RelativeForward",
}


def ps2_action_record_string_field(value: str, field_rel: int) -> str:
    if field_rel == 0x38:
        return "ActionFamily"
    if field_rel == 0x3C:
        return "ContactNode" if is_ps2_skeleton_node_name(value) else "Cue"
    if field_rel == 0x78:
        return "Animation"
    if field_rel == 0x7C:
        return "LinkedAction"
    if field_rel == 0x6C:
        return "LinkedActionA"
    if field_rel == 0x70:
        return "LinkedActionB"
    if field_rel == 0x74:
        return "LinkedActionC"
    if field_rel == 0x80:
        return "LinkedActionD"
    return "String"


def ps2_primary_action_record_starts(data: bytes | bytearray, base: int, size: int) -> tuple[int, int, set[int]]:
    primary_lookup = u32(data, base + 0x0B4C) if 0x0B50 <= size else 0
    primary_count = u32(data, base + 0x0B48) if 0x0B4C <= size else 0
    indexed_offsets = u32(data, base + 0x0B64) if 0x0B68 <= size else 0
    if not (
        primary_lookup % 4 == 0
        and indexed_offsets % 4 == 0
        and 0 < primary_lookup < indexed_offsets <= size
        and primary_count > 0
        and indexed_offsets - primary_lookup == primary_count * 0x84
    ):
        return primary_lookup, primary_count, set()
    return primary_lookup, primary_count, {primary_lookup + index * 0x84 for index in range(primary_count)}


def ps2_action_record_display_name(data: bytes | bytearray, strings: list[str], base: int, rel: int) -> str:
    for field_rel in (0x78, 0x7C, 0x38, 0x3C):
        raw = u32(data, base + rel + field_rel)
        string_index = string_id_at(data, strings, base + rel + field_rel)
        if raw != 0 and string_index is not None and is_meaningful_string(strings[string_index]):
            return meaningful_stem(strings[string_index])
    return f"Action0x{rel:06X}"


def ps2_action_input_labels(
    data: bytes | bytearray,
    strings: list[str],
    base: int,
    size: int,
    primary_action_starts: set[int],
) -> tuple[dict[int, str], dict[int, str], dict[int, str]]:
    labels: dict[int, str] = {}
    forced_types: dict[int, str] = {}
    roots: dict[int, str] = {}
    if not primary_action_starts:
        return labels, forced_types, roots
    action_lookup_start = u32(data, base + 0x0B84) if 0x0B88 <= size else 0
    trailing_start = u32(data, base + 0x0B8C) if 0x0B90 <= size else 0
    if not (action_lookup_start % 4 == 0 and 0 < action_lookup_start < size):
        return labels, forced_types, roots
    scan_end = trailing_start if trailing_start % 4 == 0 and action_lookup_start < trailing_start <= size else size
    current_owner = "Unowned"
    current_owner_start = action_lookup_start
    roots.setdefault(action_lookup_start, "ActionInputs")
    link_starts: list[int] = []
    for rel in range(action_lookup_start, scan_end - 7, 4):
        target = u32(data, base + rel)
        move_length = f32(data, base + rel + 0x04)
        if target not in primary_action_starts:
            continue
        if not math.isfinite(move_length) or not (0.01 <= abs(move_length) <= 300.0):
            continue
        current_owner = ps2_action_record_display_name(data, strings, base, target)
        current_owner_start = rel
        link_starts.append(rel)
        stem = f"ActionInput.{current_owner}"
        roots.setdefault(rel, stem)
        labels[rel] = f"{stem}.AnimationBlockRef"
        forced_types[rel] = "ref"
        labels[rel + 0x04] = f"{stem}.MoveLength"
        forced_types[rel + 0x04] = "f32"

    link_starts = sorted(link_starts)
    current_owner = "Unowned"
    link_index = 0
    for rel in range(action_lookup_start, scan_end - 15, 4):
        while link_index < len(link_starts) and link_starts[link_index] <= rel:
            target = u32(data, base + link_starts[link_index])
            current_owner = ps2_action_record_display_name(data, strings, base, target)
            current_owner_start = link_starts[link_index]
            link_index += 1
        words = [u32(data, base + rel + index * 4) for index in range(4)]
        if not (
            words[0] == 0x04
            and words[1] in PS2_INPUT_CODE_NAMES
            and words[2] in {0, 1}
            and words[3] in {0, 1}
        ):
            continue
        button = PS2_INPUT_CODE_NAMES[words[1]]
        press_state = "Press" if words[2] else "Release"
        hold_mode = "Hold" if words[3] else "Tap"
        stem = f"ActionInput.{current_owner}.ButtonPress.{button}.{press_state}.{hold_mode}"
        roots.setdefault(current_owner_start, f"ActionInput.{current_owner}")
        for field_rel, field_name in (
            (0x00, "CommandType"),
            (0x04, "InputCode"),
            (0x08, "PressState"),
            (0x0C, "HoldMode"),
        ):
            labels[rel + field_rel] = f"{stem}.{field_name}"
            forced_types[rel + field_rel] = "int"
    return labels, forced_types, roots


def ps2_action_input_owner_links(
    data: bytes | bytearray,
    strings: list[str],
    base: int,
    size: int,
    primary_action_starts: set[int],
) -> list[tuple[int, str]]:
    if not primary_action_starts:
        return []
    action_lookup_start = u32(data, base + 0x0B84) if 0x0B88 <= size else 0
    trailing_start = u32(data, base + 0x0B8C) if 0x0B90 <= size else 0
    if not (action_lookup_start % 4 == 0 and 0 < action_lookup_start < size):
        return []
    scan_end = trailing_start if trailing_start % 4 == 0 and action_lookup_start < trailing_start <= size else size
    links: list[tuple[int, str]] = []
    for rel in range(action_lookup_start, scan_end - 7, 4):
        target = u32(data, base + rel)
        move_length = f32(data, base + rel + 0x04)
        if target not in primary_action_starts:
            continue
        if not math.isfinite(move_length) or not (0.01 <= abs(move_length) <= 300.0):
            continue
        links.append((rel, ps2_action_record_display_name(data, strings, base, target)))
    return links


def ps2_action_event_owner_for_ref(action_owner_links: list[tuple[int, str]], target: int) -> tuple[str, int] | None:
    previous: tuple[int, str] | None = None
    for rel, owner in action_owner_links:
        if rel <= target:
            previous = (rel, owner)
        else:
            break
    if previous is None:
        return None
    owner_start, owner_name = previous
    delta = target - owner_start
    if 0 <= delta <= 0x800:
        return owner_name, delta
    return None


def ps2_action_event_name_at(data: bytes | bytearray, strings: list[str], base: int, rel: int, size: int) -> str:
    if rel % 4 != 0 or not (0 <= rel + 4 <= size):
        return ""
    for field_rel in (0x00, 0x10, 0x14, 0x2C, 0x30, 0x4C):
        at = rel + field_rel
        if at + 4 > size:
            continue
        string_index = string_id_at(data, strings, base + at)
        if string_index is None:
            continue
        value = strings[string_index]
        if is_meaningful_string(value):
            return meaningful_stem(value)
    return ""


PS2_RANGED_ACTION_HEADER_FIELDS = [
    (0x00, "string", "WeaponNode"),
    (0x04, "ref", "AimTransformRef"),
    (0x08, "f32", "AimTransform.MatrixXX"),
    (0x0C, "f32", "AimTransform.MatrixXY"),
    (0x10, "f32", "AimTransform.MatrixXZ"),
    (0x14, "f32", "AimTransform.MatrixYX"),
    (0x18, "f32", "AimTransform.MatrixYY"),
    (0x1C, "f32", "AimTransform.MatrixYZ"),
    (0x20, "f32", "AimTransform.MatrixZX"),
    (0x24, "f32", "AimTransform.MatrixZY"),
    (0x28, "f32", "AimTransform.MatrixZZ"),
    (0x2C, "f32", "FiringOffsetX"),
    (0x30, "f32", "FiringOffsetY"),
    (0x34, "f32", "FiringOffsetZ"),
    (0x38, "string", "FireEffect"),
]

PS2_RANGED_ACTION_EMITTER_FIELDS = [
    (0x00, "f32", "DirectionRightX"),
    (0x04, "f32", "DirectionRightY"),
    (0x08, "f32", "DirectionRightZ"),
    (0x0C, "f32", "DirectionUpX"),
    (0x10, "f32", "DirectionUpY"),
    (0x14, "f32", "DirectionUpZ"),
    (0x18, "f32", "DirectionForwardX"),
    (0x1C, "f32", "DirectionForwardY"),
    (0x20, "f32", "DirectionForwardZ"),
    (0x24, "f32", "SpawnOffsetX"),
    (0x28, "f32", "SpawnOffsetY"),
    (0x2C, "f32", "SpawnOffsetZ"),
    (0x30, "u16x2", "FrameIndexPair"),
]

PS2_INDEXED_ACTION_BASE_KIND_NAMES = {
    "f32": "Scalar",
    "u8x4": "Flags",
    "u16x2": "Pair",
    "ref": "OffsetRef",
    "int": "Packed",
}

PS2_STRUCTURAL_FIELDS: dict[int, tuple[str, str]] = {
    0x0000: ("int", "MonsterData.FormatVersion"),
    0x0B2C: ("string", "ResourceRefs.Skeleton"),
    0x0B30: ("string", "ResourceRefs.Mesh"),
    0x0B34: ("string", "IntroCamera.Node"),
    0x0B38: ("string", "IntroCamera.Resource"),
    0x0B44: ("ref", "TableRefs.PrimaryData"),
    0x0B48: ("int", "TableCounts.PrimaryData"),
    0x0B4C: ("ref", "TableRefs.PrimaryLookup"),
    0x0B50: ("ref", "TableRefs.EffectLookup"),
    0x0B58: ("ref", "TableRefs.BodyPartActionLookup"),
    0x0B5C: ("int", "TableCounts.BodyPartActionLookup"),
    0x0B60: ("ref", "TableRefs.IndexedActionBase"),
    0x0B64: ("ref", "TableRefs.IAOffsets"),
    0x0B6C: ("ref", "TableRefs.BodyPartRecords"),
    0x0B70: ("ref", "TableRefs.BodyPartDirectory"),
    0x0B78: ("ref", "TableRefs.BeamFightActions"),
    0x0B80: ("ref", "TableRefs.RangedActions"),
    0x0B84: ("ref", "TableRefs.ActionLookup"),
    0x0B8C: ("ref", "TableRefs.TrailingActions"),
}

GENERATED_LABEL_MARKERS = (
    "StringList",
    ".Entry",
    "ZeroPadding",
    "Unclassified",
    "PointerDirectory",
    "UnidentifiedReference",
    "_Alt",
    ".Alt",
    "Reserved",
)


def strip_ps2_prefix(value: str) -> str:
    value = cstr_safe(value)
    return value[3:] if value.startswith("000") and len(value) > 3 else value


def strip_label_parenthetical_suffix(value: str) -> str:
    return re.sub(r"\s*\([^)]*\)\s*$", "", value).strip()


def meaningful_stem(value: str) -> str:
    stem = clean_label(strip_label_parenthetical_suffix(strip_ps2_prefix(value))).strip("_")
    return stem or clean_label(value)


def is_ps2_skeleton_node_name(value: str) -> bool:
    plain = strip_ps2_prefix(value)
    lower = plain.lower()
    if plain.startswith("Bip"):
        return True
    if "liftnode" in lower or "lift node" in lower:
        return True
    if lower in {"lift_node", "arm - right", "arm - left", "leg - right", "leg - left", "hand - right", "hand - left", "foot - right", "foot - left", "head", "body", "neck", "tail"}:
        return True
    return False


def ps2_skeleton_node_names(
    data: bytes | bytearray,
    entries: list[dict],
    strings: list[str],
    skeleton_name: str,
) -> dict[int, str]:
    skeleton_stem = strip_ps2_prefix(skeleton_name).lower()
    skeleton_entries = [
        entry
        for entry in entries
        if not entry.get("is_resource")
        and entry.get("file_type") in {3, 4}
        and skeleton_stem
        and skeleton_stem in strip_ps2_prefix(str(entry.get("name", ""))).lower()
    ]
    skeleton_entries.sort(key=lambda entry: (0 if entry.get("file_type") == 3 else 1, int(entry.get("size", 0))))
    if not skeleton_entries:
        return {}

    for entry in skeleton_entries:
        if entry.get("file_type") != 3:
            continue
        start = int(entry.get("data_offset", entry.get("offset", 0)))
        size = int(entry.get("data_size", entry.get("size", 0)))
        if size < 0x40:
            continue
        try:
            node_count = u32(data, start + 0x20)
            node_offset_table = u32(data, start + 0x2C)
        except Exception:
            continue
        if not (0 < node_count < 512 and 0x40 <= node_offset_table <= size - node_count * 4):
            continue
        ordered: dict[int, str] = {}
        for index in range(node_count):
            record_rel = u32(data, start + node_offset_table + index * 4)
            if not (0x40 <= record_rel <= size - 0x10):
                continue
            name_id = u32(data, start + record_rel + 0x0C)
            if not (0 <= name_id < len(strings)):
                continue
            value = strings[name_id]
            if not is_ps2_skeleton_node_name(value):
                continue
            ordered[index] = strip_ps2_prefix(value)
        if ordered:
            return ordered

    ordered_names: list[str] = []
    seen: set[str] = set()
    for entry in skeleton_entries:
        start = int(entry.get("data_offset", entry.get("offset", 0)))
        size = int(entry.get("data_size", entry.get("size", 0)))
        for rel in range(0, max(0, size - 3), 4):
            raw = u32(data, start + rel)
            if not (0 <= raw < len(strings)):
                continue
            value = strings[raw]
            if not is_ps2_skeleton_node_name(value):
                continue
            plain = strip_ps2_prefix(value)
            if plain in seen:
                continue
            seen.add(plain)
            ordered_names.append(plain)
        if ordered_names:
            break
    return {index: name for index, name in enumerate(ordered_names)}


def read_fixed_ascii(data: bytes | bytearray, absolute_offset: int, size: int) -> str:
    raw = bytes(data[absolute_offset : absolute_offset + size])
    end = raw.find(b"\x00")
    if end < 0:
        end = size
    return raw[:end].decode("ascii", "replace")


def quote_text(value: str) -> str:
    return repr(value)


def unquote_text(value: str) -> str:
    value = strip_inline_comment(value).strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        try:
            return str(__import__("ast").literal_eval(value))
        except (ValueError, SyntaxError):
            return value[1:-1]
    return value


def parse_ascii_kind(kind: str) -> int | None:
    match = re.fullmatch(r"ascii\[(0x[0-9A-Fa-f]+|\d+)\]", kind)
    if not match:
        return None
    return int(match.group(1), 0)


def ascii_bytes_for_field(value: str, size: int) -> bytes:
    text = unquote_text(value)
    encoded = text.encode("ascii")
    if len(encoded) >= size:
        raise ValueError(f"ASCII field is too long for {size} bytes: {text}")
    return encoded + b"\x00" + (b"\x00" * (size - len(encoded) - 1))


def ps2_string_ref_labels(
    data: bytes | bytearray,
    strings: list[str],
    base: int,
    size: int,
    occupied: set[int],
) -> tuple[dict[int, str], dict[int, str]]:
    labels: dict[int, str] = {}
    forced_types: dict[int, str] = {}
    effect_start = u32(data, base + 0x0B50) if 0x0B54 <= size else 0
    effect_count = u32(data, base + 0x0B54) if 0x0B58 <= size else 0
    effect_end = effect_start + effect_count * 0x68 if effect_start and 0 < effect_count < 0x10000 else 0
    action_lookup_start = u32(data, base + 0x0B84) if 0x0B88 <= size else 0
    for rel in range(0, size - 3, 4):
        if rel in occupied:
            continue
        raw = u32(data, base + rel)
        string_id = string_id_at(data, strings, base + rel)
        if string_id is None:
            continue
        raw_name = cstr_safe(strings[string_id])
        stem = meaningful_stem(raw_name)
        if not stem:
            continue
        if rel < 0x1AC:
            section = "StartupRefs"
        elif 0xA90 <= rel < 0xB90:
            explicit = PS2_STARTUP_TABLE_FIELD_NAMES.get(rel)
            if explicit:
                labels[rel] = f"StartupTables.{explicit}"
                forced_types[rel] = "string"
                continue
            section = "StartupTables"
        else:
            if raw == 0:
                continue
            in_action_lookup_strings = (
                action_lookup_start % 4 == 0
                and effect_start % 4 == 0
                and action_lookup_start <= rel < effect_start
            )
            in_effect_records = effect_start <= rel < effect_end <= size
            if not (in_action_lookup_strings or in_effect_records):
                continue
            section = "StringRefs"
        label_base = f"{section}.{stem}"
        labels[rel] = label_base
        forced_types[rel] = "string"
    return labels, forced_types


def ps2_core_tuning_labels(data: bytes | bytearray, strings: list[str], base: int, size: int, occupied: set[int]) -> tuple[dict[int, str], dict[int, str]]:
    labels: dict[int, str] = {}
    forced_types: dict[int, str] = {}
    for rel in PS2_CORE_TUNING_RELS:
        if rel in occupied or rel + 4 > size:
            continue
        raw = u32(data, base + rel)
        if raw == 0:
            continue
        if string_id_at(data, strings, base + rel) is not None:
            label_tail = PS2_CORE_TUNING_FIELD_NAMES.get(rel, meaningful_stem(strings[raw]))
            labels[rel] = f"CoreTuning.{label_tail}"
            forced_types[rel] = "string"
            continue
        exponent = (raw >> 23) & 0xFF
        label_tail = PS2_CORE_TUNING_FIELD_NAMES.get(rel)
        if 0x70 <= exponent <= 0x8E and abs(f32(data, base + rel)) < 1000000.0:
            labels[rel] = f"CoreTuning.{label_tail or 'ExtraScalar'}"
            forced_types[rel] = "f32"
        else:
            labels[rel] = f"CoreTuning.{label_tail or 'ExtraPacked'}"
            forced_types[rel] = "int"
    return labels, forced_types


def ps2_value_type(data: bytes | bytearray, base: int, rel: int, size: int) -> str:
    raw = u32(data, base + rel)
    if raw % 4 == 0 and 0x100 <= raw < size:
        return "ref"
    if looks_like_u16x2(raw):
        return "u16x2"
    if looks_like_u8x4(raw):
        return "u8x4"
    exponent = (raw >> 23) & 0xFF
    value = f32(data, base + rel)
    if raw != 0 and 0x70 <= exponent <= 0x8E and abs(value) < 1000000.0:
        return "f32"
    return "int"


def ps2_action_base_string_field(value: str, used: set[str]) -> str:
    plain = strip_ps2_prefix(value)
    lower = plain.lower()
    if lower.endswith((".edf", ".prx", ".pvm", ".pwk", ".bsf", ".ifc")):
        candidates = ("Resource",)
    elif "|" in plain:
        candidates = ("NodePath",)
    elif any(token in lower for token in ("punch", "bite", "tail", "attack", "airborne", "faceup", "facedown", "spin", "block")) and not plain.isupper():
        candidates = ("ActionFamily", "TargetState", "SourceState")
    elif plain.isupper() or "_" in plain:
        candidates = ("EventName", "Animation", "CueName", "FollowupEvent")
    else:
        candidates = ("EventName", "Name", "ActionFamily")
    for candidate in candidates:
        if candidate not in used:
            used.add(candidate)
            return candidate
    return candidates[-1]


def ps2_action_base_numeric_field(kind: str, raw: int, value: float, used: set[str]) -> str:
    if raw == 0xFFFFFFFF:
        return "Sentinel"
    if kind == "f32":
        if -0.01 <= value <= 1.25:
            candidates = ("EventTime", "EndTime", "BlendWeight", "Scale")
        elif 1.25 < value <= 120.0:
            candidates = ("DurationFrames", "Radius", "Scale")
        else:
            candidates = ("Magnitude", "Scale")
    elif kind == "u8x4":
        candidates = ("Flags", "FlagsB")
    elif kind == "u16x2":
        candidates = ("FrameRange", "BoneChannelPair", "Pair")
    elif kind == "ref":
        candidates = ("LinkedOffset", "TargetOffset")
    else:
        hi = (raw >> 16) & 0xFFFF
        lo = raw & 0xFFFF
        if raw & 0x80000000:
            signed = raw - 0x100000000
        else:
            signed = raw
        if signed < 0 and hi in {0xFFFF, 0xFFFE}:
            candidates = ("FrameRange", "DisabledFrameRange")
        elif hi <= 0x100 and lo <= 0x100:
            candidates = ("FrameRange", "BoneChannelPair")
        else:
            candidates = ("Flags", "EventParam")
    for candidate in candidates:
        if candidate not in used:
            used.add(candidate)
            return candidate
    return candidates[-1]


PS2_EFFECT_STRING_FIELD_NAMES = {
    0x00: "OwnerAction",
    0x20: "TriggerAction",
    0x24: "TriggerCue",
    0x28: "SecondaryCue",
    0x2C: "TertiaryCue",
    0x30: "EffectCue",
    0x34: "HitCue",
    0x38: "BlockCue",
    0x3C: "CancelCue",
    0x48: "TargetAction",
    0x4C: "EventName",
    0x50: "SourceAction",
    0x54: "LinkedAction",
    0x58: "FollowupAction",
    0x5C: "FollowupEvent",
    0x60: "ReturnAction",
    0x64: "FallbackAction",
}


def ps2_effect_string_field(value: str, field_rel: int) -> str:
    plain = strip_ps2_prefix(value)
    lower = plain.lower()
    if lower.endswith(".edf"):
        return "Resource"
    if lower.endswith((".prx", ".pvm", ".pwk", ".bsf", ".ifc")):
        return "LinkedResource"
    explicit = PS2_EFFECT_STRING_FIELD_NAMES.get(field_rel)
    if explicit:
        return explicit
    if plain.isupper() or "_" in plain:
        return "EventName"
    return "LinkedAction"


def ps2_effect_numeric_field(kind: str, raw: int, value: float, field_rel: int) -> str:
    if kind == "f32":
        explicit = {
            0x08: "DirectionX",
            0x0C: "DirectionY",
            0x10: "DirectionZ",
            0x14: "UpX",
            0x18: "UpY",
            0x1C: "UpZ",
            0x40: "EventTime",
            0x44: "Duration",
            0x48: "Radius",
            0x4C: "Scale",
            0x54: "TargetScale",
            0x58: "SecondaryScale",
            0x5C: "Blend",
            0x60: "EndBlend",
        }.get(field_rel)
        if explicit:
            return explicit
        if -2.0 <= value <= 2.0:
            return "Blend"
        if 2.0 < value <= 120.0:
            return "Duration"
        return "Magnitude"
    if kind == "ref":
        return {
            0x04: "SpawnMaskRef",
            0x10: "PrimaryEffectRef",
            0x18: "SecondaryEffectRef",
            0x2C: "AttachmentRef",
            0x44: "EventParamRef",
            0x54: "TargetEffectRef",
            0x58: "FollowupEffectRef",
            0x60: "FallbackEffectRef",
        }.get(field_rel, "LinkedEffectRef")
    if kind == "u8x4":
        return {
            0x04: "SpawnMask",
            0x0C: "SpawnTargetMask",
            0x10: "SpawnBoneMask",
            0x44: "SpawnWindowMask",
        }.get(field_rel, "ByteMask")
    if kind == "u16x2":
        return {
            0x04: "SpawnPair",
            0x0C: "TargetPair",
            0x10: "BoneChannelPair",
            0x44: "FramePair",
        }.get(field_rel, "Pair")
    return {
        0x00: "EventFlags",
        0x04: "SpawnMaskWord",
        0x08: "EventMaskA",
        0x0C: "EventMaskB",
        0x10: "EventMaskC",
        0x18: "EffectParam",
        0x44: "EventParam",
        0x60: "FallbackParam",
    }.get(field_rel, "EventParam")


def ps2_effect_record_stem(
    data: bytes | bytearray,
    strings: list[str],
    base: int,
    record_start: int,
    _used_effect_stems: dict[str, int],
) -> str:
    def string_at(field_rel: int) -> str:
        if u32(data, base + record_start + field_rel) == 0:
            return ""
        string_index = string_id_at(data, strings, base + record_start + field_rel)
        if string_index is None:
            return ""
        value = strings[string_index]
        return value if is_meaningful_string(value) else ""

    owner = next(
        (
            string_at(field_rel)
            for field_rel in (0x00, 0x20, 0x50, 0x54, 0x48)
            if string_at(field_rel) and not strip_ps2_prefix(string_at(field_rel)).lower().endswith(".edf")
        ),
        "",
    )
    event = next(
        (
            string_at(field_rel)
            for field_rel in (0x4C, 0x5C, 0x30, 0x34, 0x24, 0x28, 0x38, 0x3C)
            if string_at(field_rel) and strip_ps2_prefix(string_at(field_rel)) != strip_ps2_prefix(owner)
        ),
        "",
    )
    resource = next((string_at(field_rel) for field_rel in range(0, 0x68, 4) if ".edf" in string_at(field_rel).lower()), "")
    stem_parts = [meaningful_stem(part) for part in (owner, event or resource) if part]
    return "EffectTable." + ".".join(stem_parts or ["Record"])


def ps2_beam_string_field(value: str, field_rel: int, used: set[str]) -> str:
    plain = strip_ps2_prefix(value)
    lower = plain.lower()
    if lower.endswith(".edf"):
        if "explosion" in lower:
            candidates = ("ExplosionResource", "ImpactResource")
        elif "pulse" in lower:
            if "red_win" in lower:
                candidates = ("RedWinPulseResource",)
            elif "red" in lower:
                candidates = ("RedPulseResource",)
            elif "green_win" in lower:
                candidates = ("GreenWinPulseResource",)
            elif "green" in lower:
                candidates = ("GreenPulseResource",)
            elif "blue_win" in lower:
                candidates = ("BlueWinPulseResource",)
            elif "blue" in lower:
                candidates = ("BluePulseResource",)
            elif "normal" in lower:
                candidates = ("NormalPulseResource",)
            else:
                candidates = ("PulseResource", "PulseResourceB", "PulseResourceC", "PulseResourceD")
        elif "strong" in lower:
            candidates = ("StrongBeamResource", "BeamResource")
        elif "weak" in lower:
            candidates = ("WeakBeamResource", "BeamResource")
        else:
            candidates = ("BeamResource", "LinkedResource")
    elif "roar" in lower or "beam" in lower or "sonic" in lower:
        candidates = ("BeamName", "BeamVariant")
    elif field_rel in {0x00, 0x04, 0x10, 0x14, 0x18, 0x38, 0x74}:
        candidates = ("PrimaryActionFamily", "SecondaryActionFamily", "LinkedActionFamily", "FollowupAction")
    else:
        candidates = ("FireCue", "HitCue", "RoarCue", "LightImpactCue", "HeavyImpactCue", "ChargeCue", "FollowupCue")
    for candidate in candidates:
        if candidate not in used:
            used.add(candidate)
            return candidate
    fallback = candidates[-1]
    used.add(fallback)
    return fallback


def ps2_beam_numeric_field(kind: str, raw: int, value: float, field_rel: int, used: set[str]) -> str:
    if kind == "f32":
        explicit = {
            0x3C: "ChargeTime",
            0x40: "PulseRate",
            0x44: "MaxRange",
            0x48: "InnerRadius",
            0x4C: "OuterRadius",
            0x50: "Damage",
            0x54: "Pushback",
            0x58: "EnergyCost",
            0x5C: "Heat",
            0x60: "ClashPower",
            0x64: "HoldTime",
            0x68: "Cooldown",
            0x6C: "Recovery",
            0x70: "RecoveryDistance",
            0x74: "WinThreshold",
            0x78: "LoseThreshold",
        }.get(field_rel)
    else:
        explicit = {
            0x74: "FollowupActionRef",
            0x78: "FollowupCueRef",
        }.get(field_rel)
    if explicit:
        used.add(explicit)
        return explicit
    if kind == "f32":
        if value < 0.0:
            candidates = ("Knockback", "Recoil", "Tuning")
        elif value <= 10.0:
            candidates = ("Scale", "Blend", "Tuning")
        elif value <= 120.0:
            candidates = ("Duration", "FrameWindow", "Tuning")
        else:
            candidates = ("Range", "Magnitude", "Tuning")
    elif kind == "ref":
        candidates = ("ActionRef", "EffectRef", "LinkedRef")
    elif kind == "u16x2":
        candidates = ("FrameRange", "BoneChannelPair", "Pair")
    elif kind == "u8x4":
        candidates = ("Flags", "ButtonMask", "ByteFlags")
    else:
        candidates = ("Flags", "EventParam", "TuningWord")
    for candidate in candidates:
        if candidate not in used:
            used.add(candidate)
            return candidate
    fallback = candidates[-1]
    used.add(fallback)
    return fallback


def ps2_owner_for_rel(rel: int, known_stems: dict[int, str], explicit_roots: dict[int, str]) -> str:
    root_items = sorted((off, stem) for off, stem in explicit_roots.items() if off <= rel)
    known_items = sorted((off, stem) for off, stem in known_stems.items() if off <= rel)
    candidates = root_items + known_items
    if candidates:
        start, stem = max(candidates, key=lambda item: item[0])
        if rel - start <= 0x1000 or start in explicit_roots:
            return meaningful_stem(stem)
    return "MonsterData"


def ps2_word_labels(
    data: bytes | bytearray,
    strings: list[str],
    base: int,
    size: int,
    occupied: set[int],
    known_stems: dict[int, str],
    explicit_roots: dict[int, str],
) -> tuple[dict[int, str], dict[int, str]]:
    labels: dict[int, str] = {}
    forced_types: dict[int, str] = {}
    effect_start = u32(data, base + 0x0B50) if 0x0B54 <= size else 0
    effect_count = u32(data, base + 0x0B54) if 0x0B58 <= size else 0
    effect_end = effect_start + effect_count * 0x68 if effect_start and 0 < effect_count < 0x10000 else 0
    trailing_start = u32(data, base + 0x0B8C) if 0x0B90 <= size else 0
    indexed_base = u32(data, base + 0x0B60) if 0x0B64 <= size else 0
    indexed_offsets = u32(data, base + 0x0B64) if 0x0B68 <= size else 0
    indexed_base_end = u32(data, base + 0x0B6C) if 0x0B70 <= size else 0
    indexed_ranges: list[tuple[int, int]] = []
    if (
        indexed_offsets % 4 == 0
        and indexed_base % 4 == 0
        and indexed_base_end % 4 == 0
        and 0 < indexed_offsets < indexed_base < indexed_base_end <= size
    ):
        indexed_base_size = indexed_base_end - indexed_base
        for rel in range(indexed_offsets, indexed_base, 4):
            raw_range = u32(data, base + rel)
            if raw_range == 0:
                continue
            start_offset = raw_range & 0xFFFF
            end_offset = (raw_range >> 16) & 0xFFFF
            end_exclusive = indexed_base_size if end_offset == 0 else end_offset + 4
            if (
                start_offset % 4 == 0
                and end_offset % 4 == 0
                and 0 <= start_offset < end_exclusive <= indexed_base_size
            ):
                indexed_ranges.append((indexed_base + start_offset, indexed_base + end_exclusive))

    def in_indexed_action_range(rel: int) -> bool:
        return any(start <= rel < end for start, end in indexed_ranges)

    for rel in range(0, size - 3, 4):
        if rel in occupied:
            continue
        if indexed_offsets <= rel < indexed_base:
            continue
        if indexed_base <= rel < indexed_base_end:
            continue
        raw = u32(data, base + rel)
        if raw == 0:
            continue
        if 0 <= raw < len(strings) and not is_meaningful_string(strings[raw]):
            continue
        kind = ps2_value_type(data, base, rel, size)
        owner = ps2_owner_for_rel(rel, known_stems, explicit_roots)
        if owner == "MonsterData" and rel >= 0xA90:
            if effect_end and rel >= effect_end and not (trailing_start % 4 == 0 and trailing_start <= rel < size):
                continue
            owner = f"DataBlock0x{(rel // 0x1000) * 0x1000:06X}"
        explicit_startup = PS2_STARTUP_TABLE_FIELD_NAMES.get(rel)
        if explicit_startup and owner == "StartupTables":
            labels[rel] = f"StartupTables.{explicit_startup}"
            forced_types[rel] = kind
            continue
        if owner == "StartupTables":
            field = {
                "f32": "ExtraScalar",
                "ref": "ExtraOffsetRef",
                "u16x2": "ExtraPair",
                "u8x4": "ExtraFlags",
                "int": "ExtraPacked",
            }[kind]
            labels[rel] = f"StartupTables.{field}"
            forced_types[rel] = kind
            continue
        field = {
            "f32": "Float",
            "ref": "Ref",
            "u16x2": "Pair",
            "u8x4": "Bytes",
            "int": "Word",
        }[kind]
        if owner.startswith("IndexedActionBase"):
            if owner == "IndexedActionBase":
                continue
            if indexed_ranges and not in_indexed_action_range(rel):
                continue
            raw_value = u32(data, base + rel)
            if raw_value == 0xFFFFFFFF:
                continue
            float_value = f32(data, base + rel) if kind == "f32" else 0.0
            field = ps2_action_base_numeric_field(kind, raw_value, float_value, set())
            labels[rel] = f"{owner}.{field}"
            forced_types[rel] = kind
            continue
        if owner in {"EffectLookup", "EffectTables"} or owner.startswith("EffectTable"):
            if not (effect_start <= rel < effect_end <= size):
                continue
            raw_value = u32(data, base + rel)
            if raw_value == 0xFFFFFFFF:
                continue
            float_value = f32(data, base + rel) if kind == "f32" else 0.0
            owner_start = containing_known_stem(known_stems, rel)
            field_rel = rel - owner_start[0] if owner_start else 0
            field = ps2_effect_numeric_field(kind, raw_value, float_value, field_rel)
            labels[rel] = f"{owner}.{field}"
            forced_types[rel] = kind
            continue
        if owner.startswith("BeamFightActions"):
            raw_value = u32(data, base + rel)
            if raw_value == 0xFFFFFFFF:
                continue
            float_value = f32(data, base + rel) if kind == "f32" else 0.0
            owner_start = containing_known_stem(known_stems, rel)
            field_rel = rel - owner_start[0] if owner_start else 0
            field = ps2_beam_numeric_field(kind, raw_value, float_value, field_rel, set())
            labels[rel] = f"{owner}.{field}"
            forced_types[rel] = kind
            continue
        labels[rel] = f"{owner}.{field}0x{rel:06X}"
        forced_types[rel] = kind
    return labels, forced_types


def ps2_structural_table_labels(
    data: bytes | bytearray,
    strings: list[str],
    base: int,
    size: int,
    skeleton_node_names: dict[int, str] | None = None,
) -> tuple[dict[int, str], dict[int, str], dict[int, str]]:
    labels: dict[int, str] = {}
    forced_types: dict[int, str] = {}
    roots: dict[int, str] = {}
    skeleton_node_names = skeleton_node_names or {}
    _primary_lookup, _primary_count, primary_action_starts = ps2_primary_action_record_starts(data, base, size)
    action_owner_links = ps2_action_input_owner_links(data, strings, base, size, primary_action_starts)

    primary_start = u32(data, base + 0x0B44) if 0x0B48 <= size else 0
    primary_end = u32(data, base + 0x0B4C) if 0x0B50 <= size else 0
    if (
        primary_start % 4 == 0
        and primary_end % 4 == 0
        and 0 < primary_start < primary_end <= size
        and (primary_end - primary_start) >= 0x18
    ):
        fields = [
            (0x00, "f32", "LocalX"),
            (0x04, "f32", "LocalY"),
            (0x08, "f32", "LocalZ"),
            (0x0C, "f32", "ReachOrArc"),
            (0x10, "f32", "Radius"),
            (0x14, "u16x2", "BoneChannelPair"),
        ]
        for rel in range(primary_start, primary_end - 0x17, 0x18):
            pair = u32(data, base + rel + 0x14)
            bone_id = pair & 0xFFFF
            node_name = skeleton_node_names.get(bone_id)
            if node_name:
                stem = f"PrimaryData.{meaningful_stem(node_name)}"
            else:
                stem = f"PrimaryData.Bone{bone_id:03d}"
            roots[rel] = stem
            for field_rel, force, field_name in fields:
                labels[rel + field_rel] = f"{stem}.{field_name}"
                forced_types[rel + field_rel] = force

    primary_lookup = u32(data, base + 0x0B4C) if 0x0B50 <= size else 0
    primary_count = u32(data, base + 0x0B48) if 0x0B4C <= size else 0
    indexed_offsets = u32(data, base + 0x0B64) if 0x0B68 <= size else 0
    action_record_size = 0x84
    if (
        primary_lookup % 4 == 0
        and indexed_offsets % 4 == 0
        and 0 < primary_lookup < indexed_offsets <= size
        and primary_count > 0
        and indexed_offsets - primary_lookup == primary_count * action_record_size
    ):
        string_slots = {
            0x38: "ActionFamily",
            0x3C: "Cue",
            0x6C: "LinkedActionA",
            0x70: "LinkedActionB",
            0x74: "LinkedActionC",
            0x78: "Animation",
            0x7C: "LinkedAction",
            0x80: "LinkedActionD",
        }
        seen_stems: dict[str, int] = {}
        for index in range(primary_count):
            rel = primary_lookup + index * action_record_size
            stem_source = None
            for slot in (0x78, 0x7C, 0x38, 0x3C):
                string_index = string_id_at(data, strings, base + rel + slot)
                if string_index is not None and is_meaningful_string(strings[string_index]):
                    stem_source = strings[string_index]
                    break
            if stem_source:
                stem_base = f"ActionRecord.{meaningful_stem(stem_source)}"
            else:
                stem_base = f"ActionRecord.Index{index:03d}"
            seen_stems[stem_base] = seen_stems.get(stem_base, 0) + 1
            stem = stem_base
            roots.setdefault(rel, stem)
            for field_rel in range(0, action_record_size, 4):
                field_abs = base + rel + field_rel
                raw = u32(data, field_abs)
                if field_rel in string_slots and string_id_at(data, strings, field_abs) is not None:
                    if raw == 0:
                        continue
                    labels[rel + field_rel] = f"{stem}.{ps2_action_record_string_field(strings[raw], field_rel)}"
                    forced_types[rel + field_rel] = "string"
                    continue
                if raw == 0 and field_rel not in PS2_ACTION_RECORD_FIELD_NAMES:
                    continue
                kind = ps2_value_type(data, base, rel + field_rel, size)
                field_name = PS2_ACTION_RECORD_FIELD_NAMES.get(field_rel)
                forced_kind = PS2_ACTION_RECORD_FIELD_TYPES.get(field_rel, kind)
                if field_name is None:
                    if kind == "f32":
                        field_name = "Scalar"
                    elif kind == "ref":
                        field_name = "LinkedOffset"
                    elif kind == "u16x2":
                        field_name = "Pair"
                    elif kind == "u8x4":
                        field_name = "Flags"
                    else:
                        field_name = "Packed"
                labels[rel + field_rel] = f"{stem}.{field_name}"
                forced_types[rel + field_rel] = forced_kind

    indexed_base = u32(data, base + 0x0B60) if 0x0B64 <= size else 0
    if (
        indexed_offsets % 4 == 0
        and indexed_base % 4 == 0
        and 0 < indexed_offsets < indexed_base <= size
    ):
        roots.setdefault(indexed_offsets, "IAOffsets")
        indexed_base_end = u32(data, base + 0x0B6C) if 0x0B70 <= size else size
        indexed_base_size = indexed_base_end - indexed_base if indexed_base < indexed_base_end <= size else 0
        indexed_offset_count = (indexed_base - indexed_offsets) // 4
        ia_index_action_names: dict[int, str] = {}
        if primary_lookup % 4 == 0 and primary_count > 0 and primary_lookup + primary_count * action_record_size <= size:
            for action_rel in range(primary_lookup, primary_lookup + primary_count * action_record_size, action_record_size):
                action_index = u32(data, base + action_rel + 0x34)
                if 0 <= action_index < indexed_offset_count:
                    ia_index_action_names.setdefault(
                        action_index,
                        ps2_action_record_display_name(data, strings, base, action_rel),
                    )
        ranges: list[tuple[int, int, int, int]] = []
        for index, rel in enumerate(range(indexed_offsets, indexed_base, 4)):
            raw = u32(data, base + rel)
            if raw == 0:
                continue
            end_offset = (raw >> 16) & 0xFFFF
            start_offset = raw & 0xFFFF
            if (
                indexed_base_size > 0
                and start_offset % 4 == 0
                and end_offset % 4 == 0
                and 0 <= start_offset < indexed_base_size
            ):
                if end_offset == 0 and index == ((indexed_base - indexed_offsets) // 4) - 1:
                    end_exclusive = indexed_base_size
                else:
                    end_exclusive = end_offset + 4
                if start_offset < end_exclusive <= indexed_base_size:
                    ranges.append((index, rel, indexed_base + start_offset, indexed_base + end_exclusive))
        used_range_stems: dict[str, int] = {}
        for index, offset_rel, start, end in ranges:
            action_name = ia_index_action_names.get(index)
            if not action_name:
                continue
            stem_base = f"IndexedActionBase.{meaningful_stem(action_name)}"
            duplicate = used_range_stems.get(stem_base, 0)
            used_range_stems[stem_base] = duplicate + 1
            stem = stem_base
            roots.setdefault(start, stem)
            used_field_names: set[str] = set()
            for rel in range(start, end, 4):
                raw = u32(data, base + rel)
                if raw == 0 or raw == 0xFFFFFFFF:
                    continue
                string_index = string_id_at(data, strings, base + rel)
                if string_index is not None:
                    field_name = ps2_action_base_string_field(strings[string_index], used_field_names)
                    labels[rel] = f"{stem}.{field_name}"
                    forced_types[rel] = "string"
                    continue
                kind = ps2_value_type(data, base, rel, size)
                value = f32(data, base + rel) if kind == "f32" else 0.0
                field_name = ps2_action_base_numeric_field(kind, raw, value, used_field_names)
                labels[rel] = f"{stem}.{field_name}"
                forced_types[rel] = kind

    ranged_start = u32(data, base + 0x0B80) if 0x0B84 <= size else 0
    action_lookup_start = u32(data, base + 0x0B84) if 0x0B88 <= size else 0
    effect_start = u32(data, base + 0x0B50) if 0x0B54 <= size else 0
    effect_count = u32(data, base + 0x0B54) if 0x0B58 <= size else 0
    effect_end = effect_start + effect_count * 0x68 if effect_start and 0 < effect_count < 0x10000 else 0
    if (
        ranged_start % 4 == 0
        and action_lookup_start % 4 == 0
        and 0 < ranged_start < action_lookup_start <= size
    ):
        roots.setdefault(ranged_start, "RangedActions")
        ranged_starts: list[int] = []
        for rel in range(ranged_start, action_lookup_start - 0x3B, 4):
            name_index = string_id_at(data, strings, base + rel)
            if name_index is None or not is_meaningful_string(strings[name_index]):
                continue
            data_ref = u32(data, base + rel + 0x04)
            cue_index = string_id_at(data, strings, base + rel + 0x38)
            if rel + 0x04 <= data_ref <= rel + 0x10 and cue_index is not None:
                ranged_starts.append(rel)
        if ranged_starts:
            ranged_starts = sorted(dict.fromkeys(ranged_starts))
            ranged_bounds = ranged_starts + [action_lookup_start]
            used_ranged_stems: dict[str, int] = {}
            for record_start, record_end in zip(ranged_bounds, ranged_bounds[1:]):
                name_index = string_id_at(data, strings, base + record_start)
                if name_index is None:
                    continue
                stem_base = f"RangedAction.{meaningful_stem(strings[name_index])}"
                duplicate = used_ranged_stems.get(stem_base, 0)
                used_ranged_stems[stem_base] = duplicate + 1
                stem = stem_base if duplicate == 0 else f"{stem_base}.Variant{duplicate + 1:02d}"
                roots.setdefault(record_start, stem)
                for field_rel, force, field_name in PS2_RANGED_ACTION_HEADER_FIELDS:
                    rel = record_start + field_rel
                    if rel >= record_end or rel >= size:
                        continue
                    raw = u32(data, base + rel)
                    if raw == 0 or (force == "string" and string_id_at(data, strings, base + rel) is None):
                        continue
                    labels[rel] = f"{stem}.{field_name}"
                    forced_types[rel] = force
                emitter_start = record_start + 0x3C
                emitter_index = 0
                while emitter_start + 0x34 <= record_end:
                    emitter_stem = f"{stem}.Emitter{emitter_index:02d}"
                    for field_rel, force, field_name in PS2_RANGED_ACTION_EMITTER_FIELDS:
                        rel = emitter_start + field_rel
                        raw = u32(data, base + rel)
                        if raw == 0:
                            continue
                        labels[rel] = f"{emitter_stem}.{field_name}"
                        forced_types[rel] = force
                    emitter_start += 0x34
                    emitter_index += 1

    if (
        effect_start % 4 == 0
        and effect_end % 4 == 0
        and 0 < effect_start < effect_end <= size
    ):
        roots.setdefault(effect_start, "EffectTables")
        used_effect_stems: dict[str, int] = {}
        for record_start in range(effect_start, effect_end, 0x68):
            string_slots_in_record: list[tuple[int, str]] = []
            for field_rel in range(0, 0x68, 4):
                if u32(data, base + record_start + field_rel) == 0:
                    continue
                string_index = string_id_at(data, strings, base + record_start + field_rel)
                if string_index is not None and is_meaningful_string(strings[string_index]):
                    string_slots_in_record.append((field_rel, strings[string_index]))
            if not string_slots_in_record:
                continue
            stem = ps2_effect_record_stem(data, strings, base, record_start, used_effect_stems)
            roots.setdefault(record_start, stem)
            for field_rel in range(0, 0x68, 4):
                rel = record_start + field_rel
                raw = u32(data, base + rel)
                if raw == 0 or raw == 0xFFFFFFFF:
                    continue
                string_index = string_id_at(data, strings, base + rel)
                if string_index is not None:
                    value = strings[string_index]
                    field_name = ps2_effect_string_field(value, field_rel)
                    labels[rel] = f"{stem}.{field_name}"
                    forced_types[rel] = "string"
                    continue
                kind = ps2_value_type(data, base, rel, size)
                value = f32(data, base + rel) if kind == "f32" else 0.0
                field_name = ps2_effect_numeric_field(kind, raw, value, field_rel)
                labels[rel] = f"{stem}.{field_name}"
                forced_types[rel] = kind

    body_action_start = u32(data, base + 0x0B58) if 0x0B5C <= size else 0
    body_action_end = u32(data, base + 0x0B78) if 0x0B7C <= size else 0
    if (
        body_action_start % 4 == 0
        and body_action_end % 4 == 0
        and 0 < body_action_start < body_action_end <= size
        and (body_action_end - body_action_start) % 0x0C == 0
    ):
        roots.setdefault(body_action_start, "BodyPartActionLookup")
        used_body_action_stems: dict[str, int] = {}
        for record_start in range(body_action_start, body_action_end, 0x0C):
            action_ref = u32(data, base + record_start + 0x04)
            owner_info = ps2_action_event_owner_for_ref(action_owner_links, action_ref)
            event_name = ps2_action_event_name_at(data, strings, base, action_ref, size)
            if owner_info:
                owner_name, _delta = owner_info
                stem_parts = [meaningful_stem(owner_name)]
                if event_name and event_name != stem_parts[0]:
                    stem_parts.append(event_name)
                stem_base = "BodyPartActionLookup." + ".".join(stem_parts)
            elif event_name:
                stem_base = f"BodyPartActionLookup.{event_name}"
            else:
                stem_base = "BodyPartActionLookup.UnresolvedActionEvent"
            duplicate = used_body_action_stems.get(stem_base, 0)
            used_body_action_stems[stem_base] = duplicate + 1
            stem = stem_base if duplicate == 0 else f"{stem_base}.Variant{duplicate + 1:02d}"
            labels[record_start] = f"{stem}.Enabled"
            forced_types[record_start] = "int"
            labels[record_start + 0x04] = f"{stem}.ActionEventRef"
            forced_types[record_start + 0x04] = "ref"
            labels[record_start + 0x08] = f"{stem}.HitResponseGroup"
            forced_types[record_start + 0x08] = "int"

    beam_start = u32(data, base + 0x0B78) if 0x0B7C <= size else 0
    beam_end = u32(data, base + 0x0B80) if 0x0B84 <= size else 0
    if beam_start % 4 == 0 and beam_end % 4 == 0 and 0 < beam_start < beam_end <= size:
        roots.setdefault(beam_start, "BeamFightActions")
        profile_size = 0x8C if (beam_end - beam_start) % 0x8C == 0 else 0x7C
        profile_starts = list(range(beam_start, beam_end, profile_size))
        weak_common_values = {
            "4foot attacks",
            "4foot punch",
            "4foot bite",
            "4foot tail",
            "ang_oof_light_rnd",
            "ang_oof_heavy_rnd",
            "ang_screech_long",
        }
        for profile_start in profile_starts:
            profile_end = min(profile_start + profile_size, beam_end)
            strings_in_profile: list[tuple[int, str]] = []
            for field_rel in range(0, profile_end - profile_start, 4):
                string_index = string_id_at(data, strings, base + profile_start + field_rel)
                if string_index is not None and is_meaningful_string(strings[string_index]):
                    strings_in_profile.append((field_rel, strings[string_index]))
            stem_source = next((value for field_rel, value in strings_in_profile if field_rel == 0x08), "")
            if stem_source and strip_ps2_prefix(stem_source).lower().endswith(".edf"):
                stem_source = ""
            if stem_source and strip_ps2_prefix(stem_source).lower() in weak_common_values:
                stem_source = ""
            if not stem_source:
                stem_source = next(
                    (
                        value
                        for _field_rel, value in strings_in_profile
                        if not strip_ps2_prefix(value).lower().endswith(".edf")
                        and strip_ps2_prefix(value).lower() not in weak_common_values
                        and ("roar" in strip_ps2_prefix(value).lower() or "beam" in strip_ps2_prefix(value).lower())
                    ),
                    "",
                )
            if not stem_source:
                stem_source = next((value for _field_rel, value in strings_in_profile if ".edf" in value.lower()), "")
            if not stem_source:
                stem_source = strings_in_profile[0][1] if strings_in_profile else "BeamProfile"
            stem = f"BeamFightActions.{meaningful_stem(stem_source)}"
            roots[profile_start] = stem
            used_field_names: set[str] = set()
            for field_rel in range(0, profile_end - profile_start, 4):
                rel = profile_start + field_rel
                raw = u32(data, base + rel)
                if raw == 0 or raw == 0xFFFFFFFF:
                    continue
                string_index = string_id_at(data, strings, base + rel)
                if string_index is not None:
                    field_name = ps2_beam_string_field(strings[string_index], field_rel, used_field_names)
                    labels[rel] = f"{stem}.{field_name}"
                    forced_types[rel] = "string"
                    continue
                kind = ps2_value_type(data, base, rel, size)
                value = f32(data, base + rel) if kind == "f32" else 0.0
                field_name = ps2_beam_numeric_field(kind, raw, value, field_rel, used_field_names)
                labels[rel] = f"{stem}.{field_name}"
                forced_types[rel] = kind

    directory = u32(data, base + 0x0B70) if 0x0B74 <= size else 0
    body_targets: list[int] = []
    if directory % 4 == 0 and 0 < directory < size:
        for rel in range(directory, min(size, directory + 0x100), 4):
            target = u32(data, base + rel)
            if not (target % 4 == 0 and 0 < target < size):
                break
            body_targets.append(target)
    for index, target in enumerate(body_targets):
        name_id = string_id_at(data, strings, base + target)
        if name_id is None:
            continue
        stem = f"BodyPart.{meaningful_stem(strings[name_id])}"
        roots.setdefault(target, stem)
        labels[target] = f"{stem}.Name"
        forced_types[target] = "string"
        if target + 0x04 < size:
            labels[target + 0x04] = f"{stem}.PrimaryReaction"
            forced_types[target + 0x04] = "string"
        if target + 0x08 < size:
            labels[target + 0x08] = f"{stem}.SecondaryReaction"
            forced_types[target + 0x08] = "string" if string_id_at(data, strings, base + target + 0x08) is not None else "int"
        next_target = body_targets[index + 1] if index + 1 < len(body_targets) else directory
        for rel in range(target + 0x0C, min(next_target, target + 0x40, size), 4):
            raw = u32(data, base + rel)
            if raw == 0:
                continue
            field_index = (rel - target - 0x0C) // 4
            if looks_like_small_u16x2(raw):
                labels[rel] = f"{stem}.BoneChannelPair{field_index}"
                forced_types[rel] = "u16x2"
            elif string_id_at(data, strings, base + rel) is not None:
                labels[rel] = f"{stem}.Action{field_index}"
                forced_types[rel] = "string"
            else:
                labels[rel] = f"{stem}.Word{field_index}"
                forced_types[rel] = "int"

    return labels, forced_types, roots


def ps2_root_lines(
    data: bytes | bytearray,
    strings: list[str],
    base: int,
    size: int,
    pointer_runs: list[dict[str, int]],
    known_stems: dict[int, str],
    fixed_ascii_by_rel: dict[int, tuple[int, str]],
) -> tuple[list[str], dict[int, str]]:
    roots: dict[int, str] = {
        0x000000: "MonsterData.Header",
        0x000004: "StartupRefs",
        0x0001AC: "CoreTuning",
        0x000A90: "StartupTables",
    }
    for rel, (_field_size, label) in fixed_ascii_by_rel.items():
        roots[rel] = label
    for rel, (kind, label) in PS2_STRUCTURAL_FIELDS.items():
        if kind != "ref" or rel + 4 > size:
            continue
        target = u32(data, base + rel)
        if target % 4 == 0 and 0 < target < size:
            roots.setdefault(target, label.replace("TableRefs.", ""))
    for target, stem in known_stems.items():
        if 0 <= target < size:
            clean_stem = meaningful_stem(stem)
            if roots.get(target) == "PrimaryData" and clean_stem.startswith("PrimaryData."):
                roots[target] = clean_stem
            elif roots.get(target) in {"BeamFightActions", "RangedActions", "BodyPartActionLookup"} and clean_stem.startswith(
                (f"{roots[target]}.",)
            ):
                roots[target] = clean_stem
            else:
                roots.setdefault(target, clean_stem)
    for run in pointer_runs:
        start = int(run["start"])
        count = int(run["count"])
        names: list[str] = []
        for entry in range(count):
            target = u32(data, base + start + entry * 4)
            name = target_record_name(data, strings, base, size, target)
            if name:
                names.append(meaningful_stem(name))
            if target in known_stems:
                names.append(known_stems[target])
        if names:
            roots.setdefault(start, f"{clean_label(names[0])}.Directory")
        else:
            roots.setdefault(start, f"ReferenceDirectory0x{start:06X}")

    body_part_start = u32(data, base + 0x0B6C) if 0x0B70 <= size else 0
    beam_start = u32(data, base + 0x0B78) if 0x0B7C <= size else 0
    beam_end = u32(data, base + 0x0B80) if 0x0B84 <= size else 0
    effect_start = u32(data, base + 0x0B50) if 0x0B54 <= size else 0

    def root_table_group(rel: int, stem: str) -> tuple[int, str]:
        key = clean_label(stem).lower()
        if body_part_start and beam_start and body_part_start <= rel < beam_start:
            return (9, "RootTables.BodyParts")
        if beam_end and effect_start and beam_end <= rel < effect_start:
            return (6, "RootTables.ActionLookups")
        if key.startswith(("monsterdata", "startuprefs", "coretuning", "startuptables", "cuenames", "resourcerefs", "introcamera")):
            return (0, "RootTables.Header")
        if key.startswith("primarydata"):
            return (1, "RootTables.PrimaryData")
        if key.startswith("primarylookup"):
            return (2, "RootTables.PrimaryLookup")
        if key.startswith("actionrecord"):
            return (3, "RootTables.ActionRecords")
        if key.startswith(("indexedactionoffsets", "iaoffsets", "iaoffset")):
            return (4, "RootTables.IAOffsets")
        if key.startswith("indexedactionbase"):
            return (5, "RootTables.IndexedActionBase")
        if key.startswith(("actionlookup", "trailingactions", "rangedactions")):
            return (6, "RootTables.ActionLookups")
        if key.startswith("effectlookup"):
            return (7, "RootTables.EffectLookup")
        if key.startswith(("effecttables", "effecttable")):
            return (8, "RootTables.EffectTables")
        if key.startswith("bodypart"):
            return (9, "RootTables.BodyParts")
        if key.startswith("beamfightactions"):
            return (10, "RootTables.BeamFightActions")
        if "directory" in key or key.endswith("lookup"):
            return (11, "RootTables.Directories")
        return (12, "RootTables.Other")

    grouped: dict[str, list[tuple[int, str]]] = {}
    group_order: dict[str, int] = {}
    for rel, stem in sorted(roots.items()):
        order, group_name = root_table_group(rel, stem)
        grouped.setdefault(group_name, []).append((rel, stem))
        group_order.setdefault(group_name, order)

    lines: list[str] = []
    if grouped:
        lines.append("# Click on table names to view contents")
    generic_toc_stems = {
        "EffectLookup",
        "IAOffsets",
        "IndexedActionOffsets",
        "IndexedActionBase",
        "PrimaryLookup",
    }
    for group_name in sorted(grouped, key=lambda name: (group_order[name], name)):
        group_entries = list(grouped[group_name])
        if group_name in {"RootTables.EffectLookup", "RootTables.IAOffsets", "RootTables.PrimaryLookup"}:
            group_entries = [
                (rel, stem)
                for rel, stem in group_entries
                if display_name(stem) not in generic_toc_stems
            ]
        elif group_name == "RootTables.IndexedActionBase":
            specific_entries = [
                (rel, stem)
                for rel, stem in group_entries
                if display_name(stem) not in generic_toc_stems
            ]
            group_entries = specific_entries
        if not group_entries:
            continue
        if lines:
            lines.append("")
        lines.append(f"[{group_name}]")
        seen_names: set[str] = set()
        for rel, stem in group_entries:
            display = display_name(stem)
            name_key = clean_label(display).lower()
            if name_key in seen_names:
                continue
            seen_names.add(name_key)
            lines.append(f"@0x{rel:06X} {display}")
    lines.append("")
    return lines, roots


def label_is_generated(label: str | None) -> bool:
    if not label:
        return True
    return any(marker in label for marker in GENERATED_LABEL_MARKERS)


def ps2_row_sort_key(rel: int) -> tuple[int, int]:
    if rel == 0:
        return (0, rel)
    if rel < 0x1AC:
        return (1, rel)
    if rel < 0x290:
        return (2, rel)
    if rel < 0xA90:
        return (3, rel)
    return (4, rel)


def ps2_spacing_section(label: str) -> str:
    parts = label.split(".")
    if len(parts) >= 4 and parts[0] == "EffectTable":
        return ".".join(parts[:3])
    if len(parts) >= 3 and parts[0] == "BodyPartActionLookup":
        return ".".join(parts[:3])
    if len(parts) >= 2 and parts[0] in {"BeamFightActions", "RangedAction"}:
        return ".".join(parts[:2])
    if len(parts) >= 2 and parts[0] in {"ActionRecord", "IndexedActionBase", "EffectTable", "BodyPart", "PrimaryData"}:
        return ".".join(parts[:2])
    return parts[0]


def ps2_skeleton_node_toc_lines(skeleton_node_names: dict[int, str]) -> list[str]:
    if not skeleton_node_names:
        return []
    lines = [
        "[RootTables.SkeletonNodes]",
        "# CMP skeleton context. BoneChannelPair first value indexes this list; these are not editable 000MONSTER_DATA offsets.",
    ]
    for index, name in sorted(skeleton_node_names.items()):
        lines.append(f"Bone{index:03d} {display_name(name)}")
    lines.append("")
    return lines


def export_txt(bundle_path: Path, out_path: Path) -> None:
    data, _parser, _entries, strings, character_data = parse_bundle(bundle_path)
    base, size = character_data_span(character_data)
    skeleton_name = ""
    if 0x0B30 <= size:
        skeleton_id = u32(data, base + 0x0B2C)
        if 0 <= skeleton_id < len(strings):
            skeleton_name = strings[skeleton_id]
    skeleton_node_names = ps2_skeleton_node_names(data, _entries, strings, skeleton_name)
    fixed_ascii_spans = {(rel, rel + field_size) for rel, field_size, _label in PS2_FIXED_ASCII_FIELDS if rel + field_size <= size}
    covered_by_ascii = {
        off
        for start, end in fixed_ascii_spans
        for off in range(start, end, 4)
    }

    chanims = scan_chanims(data, strings, base, size)
    chanim_labels = chanim_field_labels(chanims)
    mask_groups = scan_mask_groups(data, strings, base, size)
    mask_labels, mask_forced_types, mask_covered_offsets = mask_group_labels(mask_groups)
    annotate_mask_group_directory(data, base, size, mask_groups, mask_labels, mask_forced_types)
    collision_runs = scan_collision_record_runs(data, base, size)
    collision_labels, collision_forced_types = collision_record_labels(data, base, collision_runs)
    triple_runs: list[dict[str, int]] = []
    triple_labels: dict[int, str] = {}
    triple_forced_types: dict[int, str] = {}
    triple_stems: dict[int, str] = {}

    known_stems: dict[int, str] = {}
    for record in chanims:
        known_stems[int(record["rel"])] = clean_label(str(record["anim"]))
    for group in mask_groups:
        known_stems[int(group["rel"])] = clean_label(str(group["name"]))
    known_stems.update({rel: stem for rel, stem in triple_stems.items() if rel not in covered_by_ascii})

    pointer_runs = scan_pointer_runs(data, base, size)
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

    structural_labels, structural_forced_types, structural_roots = ps2_structural_table_labels(
        data,
        strings,
        base,
        size,
        skeleton_node_names,
    )
    for target, stem in structural_roots.items():
        merge_known_stem(known_stems, target, stem)

    occupied_for_strings = (
        set(covered_by_ascii)
        | set(chanim_labels)
        | set(mask_labels)
        | set(collision_labels)
        | set(triple_labels)
        | set(pointer_labels)
        | set(structural_labels)
    )
    string_labels, string_forced_types = ps2_string_ref_labels(data, strings, base, size, occupied_for_strings)
    occupied_for_tuning = set(covered_by_ascii) | set(string_labels)
    core_labels, core_forced_types = ps2_core_tuning_labels(data, strings, base, size, occupied_for_tuning)

    fixed_ascii_by_rel = {rel: (field_size, label) for rel, field_size, label in PS2_FIXED_ASCII_FIELDS if rel + field_size <= size}
    toc_lines, explicit_roots = ps2_root_lines(data, strings, base, size, pointer_runs, known_stems, fixed_ascii_by_rel)

    labels: dict[int, str] = {0: "MonsterData.FormatVersion"}
    forced_types: dict[int, str] = {0: "int"}
    for rel, (force, label) in PS2_STRUCTURAL_FIELDS.items():
        if rel < size and rel not in covered_by_ascii:
            labels[rel] = label
            forced_types[rel] = force
    for label_map, force_map in (
        (chanim_labels, {}),
        (mask_labels, mask_forced_types),
        (collision_labels, collision_forced_types),
        (triple_labels, triple_forced_types),
        (pointer_labels, pointer_forced_types),
        (structural_labels, structural_forced_types),
        (string_labels, string_forced_types),
        (core_labels, core_forced_types),
    ):
        for rel, label in label_map.items():
            if rel in covered_by_ascii or label_is_generated(label):
                continue
            if rel in PS2_STRUCTURAL_FIELDS:
                continue
            if label_map is structural_labels:
                labels[rel] = label
            else:
                labels.setdefault(rel, label)
            force = force_map.get(rel)
            if force:
                if label_map is structural_labels:
                    forced_types[rel] = force
                else:
                    forced_types.setdefault(rel, force)

    occupied_for_words = set(covered_by_ascii) | set(labels)
    word_labels, word_forced_types = ps2_word_labels(
        data,
        strings,
        base,
        size,
        occupied_for_words,
        known_stems,
        explicit_roots,
    )
    for rel, label in word_labels.items():
        if rel in covered_by_ascii or label_is_generated(label):
            continue
        labels.setdefault(rel, label)
        forced_types.setdefault(rel, word_forced_types[rel])

    lines: list[str] = [
        "# 000MONSTER_DATA text export",
        f"# SourceCMP={bundle_path}",
        f"# MonsterData={character_data['name']}",
        f"# MonsterDataOffset=0x{base:X}",
        f"# MonsterDataSize=0x{size:X}",
        "# Format: @offset <type> <name> = <value>",
        "# Types: string, float, int, ref, bool, u16x2, u8x4, ascii[SIZE].",
        "# PS2 layout notes: little-endian; padding and placeholder string id 0 are intentionally omitted.",
        "",
    ]
    lines.extend(toc_lines)
    lines.extend(ps2_skeleton_node_toc_lines(skeleton_node_names))
    lines.append("[000MONSTER_DATA]")

    record_starts = {int(record["rel"]): record for record in chanims}
    previous_section = ""
    export_rels = set(labels) | set(fixed_ascii_by_rel)
    for rel in sorted(export_rels, key=ps2_row_sort_key):
        if rel < 0 or rel >= size:
            continue
        record = record_starts.get(rel)
        if record is not None:
            lines.append("")
            lines.append(f"## ChAnimResource 000MONSTER_DATA+0x{rel:06X} {record['name']} / {record['anim']}")
        if rel in fixed_ascii_by_rel:
            field_size, label = fixed_ascii_by_rel[rel]
            section = ps2_spacing_section(label)
            if previous_section and section != previous_section and lines[-1] != "":
                lines.append("")
            previous_section = section
            value_text = quote_text(read_fixed_ascii(data, base + rel, field_size))
            lines.append(f"@0x{rel:06X} ascii[0x{field_size:X}] {label} = {value_text}")
            continue
        label = labels.get(rel)
        if label_is_generated(label):
            continue
        section = ps2_spacing_section(label)
        if previous_section and section != previous_section and lines[-1] != "":
            lines.append("")
        previous_section = section
        force = forced_types.get(rel)
        if force is None and rel in mask_covered_offsets:
            raw = u32(data, base + rel)
            if looks_like_u16x2(raw):
                force = "u16x2"
            elif looks_like_u8x4(raw):
                force = "u8x4"
        row_type, value_text = export_row_type_and_value(data, strings, base + rel, force)
        if row_type == "ref":
            raw = u32(data, base + rel)
            value_text = ref_value_text(raw, size, labels, explicit_roots, known_stems)
            if label.startswith("BodyPartActionLookup.") and label.endswith(".ActionEventRef") and re.match(r"^-?\d+$", value_text):
                value_text = display_name(label[: -len(".ActionEventRef")].replace("BodyPartActionLookup.", "ActionEvent.", 1))
            if label.startswith("BodyPartActionLookup.Ref0x") and value_text and not re.match(r"^-?\d+$", value_text):
                label = f"BodyPartActionLookup.{clean_label(value_text)}"
        lines.append(f"@0x{rel:06X} {row_type:<12} {label} = {value_text}")

    out_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"Wrote {out_path}")
    print(f"Exported {len(export_rels)} named 000MONSTER_DATA values.")
    print(f"Annotated {len(chanims)} ChAnimResource records.")
    print(f"Annotated {len(mask_groups)} mask groups.")
    print(f"Annotated {len(collision_runs)} collision record runs.")
    print(f"Annotated {len(triple_runs)} string triplet runs.")
    print(f"Annotated {len(pointer_runs)} reference runs.")
    return

    chanims = scan_chanims(data, strings, base, size)
    chanim_labels = chanim_field_labels(chanims)
    mask_groups = scan_mask_groups(data, strings, base, size)
    mask_labels, mask_forced_types, mask_covered_offsets = mask_group_labels(mask_groups)
    annotate_mask_group_directory(data, base, size, mask_groups, mask_labels, mask_forced_types)
    header_labels: dict[int, str] = {}
    header_forced_types: dict[int, str] = {}
    header_target_stems: dict[int, str] = {}
    script_labels: dict[int, str] = {}
    script_forced_types: dict[int, str] = {}
    script_stems: dict[int, str] = {}
    collision_runs = scan_collision_record_runs(data, base, size)
    collision_labels, collision_forced_types = collision_record_labels(data, base, collision_runs)
    triple_runs = scan_string_triple_runs(data, strings, base, size)
    triple_labels, triple_forced_types, triple_stems = string_triple_labels(data, strings, base, triple_runs)
    string_runs = scan_string_index_runs(data, strings, base, size)
    string_labels, string_forced_types, string_stems = string_index_run_labels(
        data,
        strings,
        base,
        string_runs,
        occupied=(
            set(chanim_labels)
            | set(mask_labels)
            | set(header_labels)
            | set(script_labels)
            | set(collision_labels)
            | set(triple_labels)
        ),
    )

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
    known_stems.update(string_stems)
    known_stems.update(header_target_stems)
    known_stems.update(script_stems)

    pointer_runs = scan_pointer_runs(data, base, size)
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
        | set(string_labels)
        | set(pointer_labels)
    )
    zero_labels, zero_forced_types = zero_run_labels(data, base, size, occupied_offsets)
    occupied_offsets |= set(zero_labels)
    generic_labels, generic_forced_types = generic_owned_range_labels(data, strings, base, size, known_stems, occupied_offsets)
    occupied_offsets |= set(generic_labels)
    fallback_labels = fallback_region_labels(size, occupied_offsets)

    major_string_roots = {
        int(run["start"]): string_stems[int(run["start"])]
        for run in string_runs
        if int(run["count"]) >= 10 and int(run["start"]) in string_stems
    }
    toc_lines = root_toc_lines(
        data,
        strings,
        base,
        size,
        pointer_runs,
        mask_groups,
        header_target_stems,
        extra_roots=major_string_roots,
    )

    lines: list[str] = [
        "# 000MONSTER_DATA text export",
        f"# SourceCMP={bundle_path}",
        f"# MonsterData={character_data['name']}",
        f"# MonsterDataOffset=0x{base:X}",
        f"# MonsterDataSize=0x{size:X}",
        "# Format: @offset <type> <name> = <value>",
        "# Types: string, float, int, ref, bool, u16x2, u8x4. Existing old-style f:/s:/hex imports are still accepted.",
        "",
    ]
    lines.extend(toc_lines)
    lines.append("[000MONSTER_DATA]")

    record_starts = {int(record["rel"]): record for record in chanims}
    previous_chunk = ""
    for rel in range(0, size - 3, 4):
        record = record_starts.get(rel)
        if record is not None:
            lines.append("")
            lines.append(f"## ChAnimResource 000MONSTER_DATA+0x{rel:06X} {record['name']} / {record['anim']}")
        absolute = base + rel
        label = (
            chanim_labels.get(rel)
            or mask_labels.get(rel)
            or header_labels.get(rel)
            or script_labels.get(rel)
            or collision_labels.get(rel)
            or triple_labels.get(rel)
            or string_labels.get(rel)
            or pointer_labels.get(rel)
            or generic_labels.get(rel)
            or zero_labels.get(rel)
            or fallback_labels.get(rel)
        )
        if label is None:
            label = f"UnclassifiedRegion.Fallback0x{rel:06X}"
        chunk = chunk_key(label)
        if previous_chunk and chunk != previous_chunk and (not lines or lines[-1] != ""):
            lines.append("")
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
            or string_forced_types.get(rel)
            or pointer_forced_types.get(rel)
            or generic_forced_types.get(rel)
            or zero_forced_types.get(rel)
        )
        if record_rel is not None:
            if field_rel in CHANIM_STRING_FIELDS:
                force = "string"
            elif field_rel in CHANIM_F32_FIELDS:
                force = "f32"
            elif field_rel in CHANIM_U32_FIELDS:
                force = "int"
        if force is None and rel in mask_covered_offsets:
            raw = u32(data, absolute)
            if looks_like_u16x2(raw):
                force = "u16x2"
            elif looks_like_u8x4(raw):
                force = "u8x4"
        row_type, value_text = export_row_type_and_value(data, strings, absolute, force)
        lines.append(f"@0x{rel:06X} {row_type:<8} {label} = {value_text}")

    out_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"Wrote {out_path}")
    print(f"Exported {size // 4} aligned 000MONSTER_DATA words.")
    print(f"Annotated {len(chanims)} ChAnimResource records.")
    print(f"Annotated {len(mask_groups)} mask groups.")
    print(f"Annotated {len(collision_runs)} collision record runs.")
    print(f"Annotated {len(triple_runs)} string triplet runs.")
    print(f"Annotated {len(string_runs)} string-list runs.")
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
    value = value.strip()
    at_match = re.match(r"^@?(0x[0-9A-Fa-f]+|\d+)\b", value)
    if at_match:
        return int(at_match.group(1), 0) & 0xFFFFFFFF
    return int(value, 0) & 0xFFFFFFFF


def parse_new_value(kind: str, value: str, strings: list[str], ref_lookup: dict[str, int] | None = None) -> bytes:
    value = strip_inline_comment(value)
    ascii_size = parse_ascii_kind(kind)
    if ascii_size is not None:
        return ascii_bytes_for_field(value, ascii_size)
    if kind in {"word", "int", "ref"}:
        if value.lower().startswith("f:"):
            return struct.pack("<f", float(value[2:].strip()))
        if value.lower().startswith("s:"):
            return parse_string_value(value[2:].strip(), strings).to_bytes(4, "little")
        if kind == "ref" and ref_lookup is not None:
            try:
                return parse_u32_value(value).to_bytes(4, "little")
            except ValueError:
                key = ref_lookup_key(value)
                if key in ref_lookup:
                    return int(ref_lookup[key]).to_bytes(4, "little")
                raise
        return parse_u32_value(value).to_bytes(4, "little")
    if kind == "string":
        if value.lower().startswith("s:"):
            value = value[2:].strip()
        return parse_string_value(value, strings).to_bytes(4, "little")
    if kind == "u32":
        return parse_u32_value(value).to_bytes(4, "little")
    if kind == "bool":
        normalized = value.strip().lower()
        if normalized in {"true", "yes", "on", "1"}:
            return (1).to_bytes(4, "little")
        if normalized in {"false", "no", "off", "0"}:
            return (0).to_bytes(4, "little")
        raise ValueError(f"bool value must be true/false or 1/0: {value}")
    if kind == "f32":
        return struct.pack("<f", float(value.strip()))
    if kind == "float":
        raw = value[2:].strip() if value.lower().startswith("f:") else value.strip()
        return struct.pack("<f", float(raw))
    if kind == "u16x2":
        parts = [part.strip() for part in value.split(",")]
        if len(parts) != 2:
            raise ValueError(f"u16x2 needs two comma-separated values: {value}")
        lo, hi = (int(part, 0) & 0xFFFF for part in parts)
        return ((hi << 16) | lo).to_bytes(4, "little")
    if kind == "u8x4":
        parts = [part.strip() for part in value.split(",")]
        if len(parts) != 4:
            raise ValueError(f"u8x4 needs four comma-separated values: {value}")
        raw = 0
        for part in parts:
            raw = (raw << 8) | (int(part, 0) & 0xFF)
        return raw.to_bytes(4, "little")
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
        raw_source = meta.get("SourceCMP") or meta.get("SourceBDG")
        bundle_path = Path(raw_source) if raw_source else None
    if bundle_path is None or not bundle_path.exists():
        bundle_path = pick_open_file(
            "Select CMP bundle to update",
            [("CMP bundles", "*.cmp *.CMP"), ("All files", "*.*")],
            GAME_DIR,
        )
    bundle_path = (ROOT / bundle_path).resolve() if not bundle_path.is_absolute() else bundle_path.resolve()

    data, _parser, _entries, strings, character_data = parse_bundle(bundle_path)
    base, size = character_data_span(character_data)
    changes: list[dict[str, object]] = []
    wanted: dict[int, tuple[str, bytes, str, str]] = {}
    conflicts: list[str] = []
    text = txt_path.read_text(encoding="utf-8")
    ref_lookup = build_ref_name_lookup_from_text(text)
    augment_ref_lookup_with_current_refs(text, data, base, size, ref_lookup)
    ref_name_counts = ref_value_name_counts_from_text(text)

    for line in text.splitlines():
        match = ROW_RE.match(line.strip())
        if not match:
            continue
        rel = int(match.group(1), 16)
        kind = match.group(2)
        label = match.group(3).strip()
        value_text = match.group(4).strip()
        ascii_size = parse_ascii_kind(kind)
        if ascii_size is None and kind not in {"string", "u32", "f32", "float", "int", "word", "ref", "bool", "u16x2", "u8x4"}:
            continue
        edit_size = ascii_size or 4
        if rel < 0 or rel + edit_size > size or rel % 4:
            continue
        absolute = base + rel
        old_bytes = bytes(data[absolute : absolute + edit_size])
        clean_value = strip_inline_comment(value_text)
        if kind == "string":
            compare_value = clean_value[2:].strip() if clean_value.lower().startswith("s:") else clean_value
            if compare_value == string_value(data, strings, absolute):
                continue
        if kind == "ref":
            clean_ref_value = strip_inline_comment(value_text).strip()
            try:
                parse_u32_value(clean_ref_value)
            except ValueError:
                key = ref_lookup_key(clean_ref_value)
                target = ref_lookup.get(key)
                old_raw = u32(data, absolute)
                if target is None or target != old_raw:
                    continue
        new_bytes = parse_new_value(kind, value_text, strings, ref_lookup)
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
        ascii_size = parse_ascii_kind(kind)
        if ascii_size is not None:
            old_text = quote_text(read_fixed_ascii(data, absolute, ascii_size))
            data[absolute : absolute + ascii_size] = new_bytes
            new_text = quote_text(read_fixed_ascii(data, absolute, ascii_size))
        else:
            old_text = row_value(data, strings, absolute, kind)
            data[absolute : absolute + 4] = new_bytes
            new_text = row_value(data, strings, absolute, kind)
        changes.append(
            {
                "offset": f"000MONSTER_DATA+0x{rel:06X}",
                "type": kind,
                "label": label,
                "old": old_text,
                "new": new_text,
                "requested": value_text,
            }
        )

    if not changes:
        print("No changed editable 000MONSTER_DATA values found.")
        return

    print(f"{'Would apply' if dry_run else 'Applying'} {len(changes)} 000MONSTER_DATA changes to {bundle_path}:")
    for change in changes[:60]:
        print(f"  {change['offset']} {change['label']}: {change['old']} -> {change['new']}")
    if len(changes) > 60:
        print(f"  ... {len(changes) - 60} more")

    if dry_run:
        return

    backup_dir = BACKUP_ROOT / f"monster_data_txt_import_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
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
    print("000MONSTER_DATA TXT Tool")
    print("1. Export 000MONSTER_DATA to txt")
    print("2. Import txt back into 000MONSTER_DATA")
    choice = ask("Choose mode", "1")
    if choice == "1":
        bundle_path = pick_open_file(
            "Select character CMP bundle",
            [("CMP bundles", "*.cmp *.CMP"), ("All files", "*.*")],
            GAME_DIR,
        )
        out_path = pick_save_file(
            "Save 000MONSTER_DATA txt",
            f"{bundle_path.stem}_Data.txt",
            [("Text files", "*.txt"), ("All files", "*.*")],
        )
        export_txt(bundle_path, out_path)
    elif choice == "2":
        txt_path = pick_open_file(
            "Select edited 000MONSTER_DATA txt",
            [("Text files", "*.txt"), ("All files", "*.*")],
            ROOT,
        )
        import_txt(txt_path)
    else:
        raise ValueError("Choose 1 or 2")
    return 0


def cli_main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Export/import editable PS2 000MONSTER_DATA rows.")
    sub = parser.add_subparsers(dest="cmd")

    export_p = sub.add_parser("export", help="Export a character CMP's 000MONSTER_DATA to txt.")
    export_p.add_argument("cmp", type=Path)
    export_p.add_argument("--out", type=Path)

    import_p = sub.add_parser("import", help="Import edited 000MONSTER_DATA txt into its source CMP.")
    import_p.add_argument("txt", type=Path)
    import_p.add_argument("--cmp", type=Path, help="Override SourceCMP from the txt.")
    import_p.add_argument("--dry-run", action="store_true")

    args = parser.parse_args(argv)
    if args.cmd is None:
        return interactive_main()
    if args.cmd == "export":
        out = args.out or Path(f"{args.cmp.stem}_Data.txt")
        export_txt(args.cmp, out)
        return 0
    if args.cmd == "import":
        import_txt(args.txt, args.cmp, args.dry_run)
        return 0
    parser.error("unknown command")
    return 2


def main() -> int:
    return cli_main(sys.argv[1:])


if __name__ == "__main__":
    raise SystemExit(main())
