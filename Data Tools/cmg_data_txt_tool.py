#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ast
import math
import re
import shutil
import struct
import sys
from datetime import datetime
from pathlib import Path


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

ROW_RE = re.compile(r"^@0x([0-9A-Fa-f]+)\s+([a-zA-Z0-9_]+(?:\[[0-9A-Fa-fxX]+\])?)\s+(.+?)\s+=\s+(.*)$")
META_RE = re.compile(r"^#\s*([^=]+?)=(.*)$")

PLACEHOLDER_STRINGS = {"", "000"}

CORE_FIELDS: dict[int, tuple[str, str]] = {
    0x000: ("int", "MonsterData.FormatTag"),
    0x004: ("float", "TypeModifier.CameraShakeScale"),
    0x008: ("float", "TypeModifier.CameraShakeAngle"),
    0x00C: ("float", "TypeModifier.MinTurnInput"),
    0x010: ("float", "TypeModifier.TurnInputScale"),
    0x014: ("float", "TypeModifier.FrameTime"),
    0x018: ("float", "TypeModifier.RightAngleRadians"),
    0x01C: ("float", "TypeModifier.ForwardArcRadians"),
    0x020: ("float", "TypeModifier.StepArcRadians"),
    0x028: ("float", "CoreTuning.Health"),
    0x02C: ("float", "CoreTuning.Energy"),
    0x030: ("float", "CoreTuning.Gravity"),
    0x034: ("float", "CoreTuning.Weight"),
    0x038: ("float", "CoreTuning.ThrowWeight"),
    0x03C: ("float", "CoreTuning.KnockbackResistance"),
    0x040: ("float", "TypeResistances.Type00"),
    0x044: ("float", "TypeResistances.Type01"),
    0x048: ("float", "TypeResistances.Type02"),
    0x04C: ("float", "TypeResistances.Type03"),
    0x050: ("float", "TypeResistances.Type04"),
    0x054: ("float", "TypeResistances.Type05"),
    0x05C: ("float", "CoreTuning.Movement.WalkSpeed"),
    0x060: ("float", "CoreTuning.Movement.RunSpeed"),
    0x064: ("float", "CoreTuning.Movement.TurnAcceleration"),
    0x068: ("float", "CoreTuning.Movement.GroundAcceleration"),
    0x06C: ("float", "CoreTuning.Movement.AirAcceleration"),
    0x070: ("float", "CoreTuning.Movement.BrakeScale"),
    0x074: ("float", "CoreTuning.Movement.StepScale"),
    0x078: ("float", "CoreTuning.Movement.JumpImpulse"),
    0x0B0: ("float", "CoreTuning.GrabRange"),
    0x0B4: ("float", "CoreTuning.GrabHeight"),
    0x0BC: ("float", "CoreTuning.ThrowRange"),
    0x0C0: ("float", "CoreTuning.AttackRange"),
    0x0C4: ("float", "CoreTuning.BlockRange"),
    0x0C8: ("float", "CoreTuning.ShortRange"),
    0x0CC: ("float", "CoreTuning.MidRange"),
    0x0D0: ("float", "CoreTuning.LongRange"),
    0x0D4: ("float", "CoreTuning.ProjectileRange"),
    0x0D8: ("float", "CoreTuning.BeamChargeRate"),
    0x0DC: ("float", "CoreTuning.CollisionRadius"),
    0x148: ("string", "Resources.Skeleton"),
    0x14C: ("string", "Resources.MeshFile"),
    0x150: ("string", "Resources.IntroCameraNode"),
    0x154: ("string", "Resources.IntroCamera"),
}

ACTION_RECORD_FIELDS: list[tuple[int, str, str]] = [
    (0x00, "string", "Animation"),
    (0x04, "string", "State"),
    (0x08, "float", "AnimRate"),
    (0x0C, "float", "TurnSpeed"),
    (0x10, "float", "Acceleration"),
    (0x14, "float", "FacingSnapSpeed"),
    (0x18, "float", "TransitionControl"),
    (0x1C, "float", "TransitionSpeed"),
    (0x20, "float", "ElevationControl"),
    (0x24, "float", "TerrainConformScale"),
    (0x28, "float", "DimensionShiftX"),
    (0x2C, "float", "DimensionShiftZ"),
    (0x30, "u16x2", "MoveEventCountFirstIndex"),
    (0x34, "ref", "LinkedActionRef"),
    (0x38, "int", "ActionIndex"),
    (0x3C, "int", "ActionFlags"),
    (0x40, "float", "AIScoreDistance"),
    (0x44, "float", "AIScoreHeight"),
    (0x48, "float", "AIScoreRange"),
    (0x4C, "float", "AIScoreWeight"),
    (0x50, "float", "AIScoreDirectionX"),
    (0x54, "float", "AIScoreDirectionZ"),
    (0x58, "float", "AIScoreFacing"),
    (0x5C, "u8x4", "AIControlFlags"),
    (0x60, "int", "AICategory"),
]

GC_MOVE_EVENT_TYPE_NAMES = {
    0: "AttackProperty",
    2: "FootStep",
    6: "Sound",
    8: "Deactivate",
    9: "ActionState",
    11: "FloatParameter",
    13: "PlayEventSound",
    17: "BodyContact",
    27: "MovementParameter",
}

# Xbox DAMM uses the GameCube 0x50-byte record after a larger header.
MONSTER_WEAPON_FIELDS: tuple[tuple[int, str, str], ...] = (
    (0x00, "int", "WeaponType"),
    (0x04, "int", "WeaponFlags"),
    (0x08, "string", "Name"),
    (0x0C, "string", "Resource0"),
    (0x10, "string", "Resource1"),
    (0x14, "string", "Resource2"),
    (0x18, "string", "Resource3"),
    (0x1C, "float", "Damage"),
    (0x20, "float", "Value0x20"),
    (0x24, "int", "Flags0x24"),
    (0x28, "float", "Range"),
    (0x2C, "float", "Value0x2C"),
    (0x30, "float", "Scale0x30"),
    (0x34, "int", "AttachmentNodeIndex"),
    (0x38, "int", "AttachmentNodeCount"),
    (0x3C, "int", "Flags0x3C"),
    (0x40, "string", "ActionName"),
    (0x44, "int", "ActionIndex"),
    (0x48, "int", "Value0x48"),
    (0x4C, "int", "Value0x4C"),
)


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
    from GZBuildr import PipeworksParser

    return PipeworksParser


PipeworksParser = load_light_bdg()


def clean_text(value: str) -> str:
    value = value.replace("\r", " ").replace("\n", " ")
    value = value.replace("\x13", "").strip()
    if value.endswith("3") and len(value) > 1:
        value = value[:-1]
    return value.strip()


def clean_label(value: str) -> str:
    value = clean_text(value)
    value = value.replace("|", "_")
    value = re.sub(r"\s+", "_", value)
    value = re.sub(r"[^0-9A-Za-z_.()\\-]+", "_", value)
    value = re.sub(r"_+", "_", value).strip("._")
    return value or "Value"


def display_name(value: str) -> str:
    return clean_label(value)


def quote_text(value: str) -> str:
    if value == "" or any(ch.isspace() for ch in value) or "#" in value:
        return repr(value)
    return value


def strip_inline_comment(value: str) -> str:
    return value.split(" #", 1)[0].strip()


def u32(data: bytes | bytearray, offset: int) -> int:
    return struct.unpack_from(">I", data, offset)[0]


def put_u32(data: bytearray, offset: int, value: int) -> None:
    struct.pack_into(">I", data, offset, value & 0xFFFFFFFF)


def f32(data: bytes | bytearray, offset: int) -> float:
    return struct.unpack_from(">f", data, offset)[0]


def put_f32(data: bytearray, offset: int, value: float) -> None:
    struct.pack_into(">f", data, offset, float(value))


def u16x2_text(raw: int) -> str:
    return f"{(raw >> 16) & 0xFFFF}, {raw & 0xFFFF}"


def u8x4_text(raw: int) -> str:
    return ", ".join(str((raw >> shift) & 0xFF) for shift in (24, 16, 8, 0))


def parse_bundle(bundle_path: Path):
    data = bytearray(bundle_path.read_bytes())
    parser = PipeworksParser(bundle_path)
    entries = parser.parse_from_data(bytes(data))
    if entries and "error" in entries[0]:
        raise RuntimeError(entries[0]["error"])
    strings = read_pipeworks_strings(data, int(getattr(parser, "string_offset", 0)))
    character_data = next(
        (
            entry for entry in entries
            if int(entry.get("file_type", -1)) == 2
            and not entry.get("is_resource")
            and Path(str(entry.get("name", "")).replace("\\", "/")).name.lower().startswith("monster_data")
        ),
        None,
    )
    if character_data is None:
        raise RuntimeError(f"{bundle_path} has no type-2 MONSTER_DATA entry")
    character_data["endian"] = ">"
    return data, parser, entries, strings, character_data


def read_pipeworks_strings(data: bytes | bytearray, string_offset: int) -> list[str]:
    if string_offset <= 0 or string_offset + 4 > len(data):
        return []
    count = struct.unpack_from("<I", data, string_offset)[0]
    if count <= 0 or count > 100000:
        return []
    offsets = []
    for index in range(count):
        pos = string_offset + 4 + index * 4
        if pos + 4 > len(data):
            break
        offsets.append(struct.unpack_from("<I", data, pos)[0])
    strings = []
    for offset in offsets:
        pos = string_offset + offset
        if pos < string_offset or pos >= len(data):
            strings.append("")
            continue
        end = pos
        while end < len(data) and data[end] != 0:
            end += 1
        strings.append(clean_text(bytes(data[pos:end]).decode("ascii", "ignore")))
    return strings


def character_data_span(entry: dict) -> tuple[int, int]:
    return int(entry.get("data_offset", entry["offset"])), int(entry.get("data_size", entry["size"]))


def string_value(strings: list[str], raw: int) -> str:
    if 0 <= raw < len(strings):
        return strings[raw]
    return str(raw)


def row_value(data: bytes | bytearray, strings: list[str], absolute_offset: int, kind: str) -> str:
    raw = u32(data, absolute_offset)
    if kind == "string":
        return quote_text(string_value(strings, raw))
    if kind == "float":
        return repr(float(f32(data, absolute_offset)))
    if kind in {"int", "ref"}:
        return str(raw if raw < 0x80000000 else raw - 0x100000000)
    if kind == "u16x2":
        return u16x2_text(raw)
    if kind == "u8x4":
        return u8x4_text(raw)
    return str(raw)


def is_probable_string_id(strings: list[str], raw: int) -> bool:
    if raw <= 0 or raw >= len(strings):
        return False
    text = strings[raw]
    return text not in PLACEHOLDER_STRINGS and len(text) >= 2


def is_probable_float(value: float) -> bool:
    return math.isfinite(value) and abs(value) <= 100000.0


def action_record_name(data: bytes | bytearray, strings: list[str], base: int, rel: int, size: int) -> str | None:
    if rel < 0 or rel + 0x64 > size:
        return None
    anim_id = u32(data, base + rel)
    state_id = u32(data, base + rel + 4)
    if not is_probable_string_id(strings, anim_id) or not is_probable_string_id(strings, state_id):
        return None
    anim_rate = f32(data, base + rel + 8)
    if not is_probable_float(anim_rate) or abs(anim_rate) < 0.001 or abs(anim_rate) > 10.0:
        return None
    return clean_label(strings[anim_id])


def scan_action_records(data: bytes | bytearray, strings: list[str], base: int, size: int) -> list[int]:
    hits = []
    for rel in range(0, max(0, size - 0x64 + 1), 4):
        if action_record_name(data, strings, base, rel, size):
            hits.append(rel)
    runs: list[list[int]] = []
    run: list[int] = []
    for rel in hits:
        if run and rel == run[-1] + 0x64:
            run.append(rel)
        else:
            if run:
                runs.append(run)
            run = [rel]
    if run:
        runs.append(run)
    if not runs:
        return []
    best = max(runs, key=len)
    return best if len(best) >= 8 else []


def scan_string_refs(
    data: bytes | bytearray,
    strings: list[str],
    base: int,
    size: int,
    occupied: set[int],
) -> dict[int, str]:
    labels = {}
    for rel in range(0, size - 3, 4):
        if rel in occupied:
            continue
        raw = u32(data, base + rel)
        if is_probable_string_id(strings, raw):
            labels[rel] = f"StringRefs.{clean_label(strings[raw])}"
    return labels


def scan_pointer_refs(
    data: bytes | bytearray,
    base: int,
    size: int,
    occupied: set[int],
    action_starts: list[int],
) -> dict[int, str]:
    starts = set(action_starts)
    labels = {}
    for rel in range(0, size - 3, 4):
        if rel in occupied:
            continue
        raw = u32(data, base + rel)
        if raw in starts:
            labels[rel] = "ActionRecordRef"
        elif raw % 4 == 0 and 0 <= raw < size and raw not in {0, rel}:
            labels[rel] = "DataRef"
    return labels


def export_txt(bundle_path: Path, out_path: Path) -> None:
    data, _parser, _entries, strings, character_data = parse_bundle(bundle_path)
    base, size = character_data_span(character_data)

    action_starts = scan_action_records(data, strings, base, size)
    action_names = {
        rel: action_record_name(data, strings, base, rel, size) or f"Action0x{rel:06X}"
        for rel in action_starts
    }
    labels: dict[int, tuple[str, str]] = {}
    for rel, spec in CORE_FIELDS.items():
        if rel + 4 <= size:
            labels[rel] = spec

    for rel in action_starts:
        record_name = action_record_name(data, strings, base, rel, size)
        if not record_name:
            continue
        for field_rel, kind, field_name in ACTION_RECORD_FIELDS:
            labels[rel + field_rel] = (kind, f"ActionRecord.{record_name}.{field_name}")

    event_count = u32(data, base + 0x16C) if size >= 0x178 else 0
    event_base = u32(data, base + 0x170) if size >= 0x178 else 0
    event_offsets = u32(data, base + 0x174) if size >= 0x178 else 0
    event_action_names: dict[int, str] = {}
    if 0 < event_count < 0x10000:
        for action_rel in action_starts:
            packed = u32(data, base + action_rel + 0x30)
            count = (packed >> 16) & 0xFFFF
            first = packed & 0xFFFF
            for event_index in range(first, min(first + count, event_count)):
                event_action_names.setdefault(event_index, action_names[action_rel])
    valid_events = (
        0 < event_count < 0x10000
        and event_offsets % 2 == 0
        and event_base % 4 == 0
        and 0 < event_offsets < event_base < size
        and event_offsets + event_count * 2 <= event_base
    )
    event_roots: list[tuple[int, str]] = []
    reserved_offsets: set[int] = set()
    if valid_events:
        reserved_offsets.update(range(event_offsets, event_base, 4))
        for event_index in range(event_count):
            start_offset = struct.unpack_from(">H", data, base + event_offsets + event_index * 2)[0]
            start = event_base + start_offset
            if event_index + 1 < event_count:
                end_offset = struct.unpack_from(">H", data, base + event_offsets + (event_index + 1) * 2)[0]
                end = event_base + end_offset
            else:
                lookup_start = u32(data, base + 0x184) if size >= 0x188 else size
                end = lookup_start if start < lookup_start <= size else size
            if not (event_base <= start < end <= size) or end - start < 4:
                continue
            reserved_offsets.update(range(start, end, 4))
            event_type = u32(data, base + start)
            if event_type >= 0x100:
                continue
            type_name = GC_MOVE_EVENT_TYPE_NAMES.get(event_type, f"Type{event_type:02d}")
            action_name = event_action_names.get(event_index, f"Index{event_index:04d}")
            stem = f"MoveEvent.{action_name}.Event{event_index:04d}_{type_name}"
            event_roots.append((start, stem))
            labels[start] = ("int", f"{stem}.Type")
            if start + 8 <= end:
                labels[start + 4] = ("float", f"{stem}.EventTime")
            if event_type == 0 and end - start >= 0x28:
                attack_fields = (
                    (0x08, "u16x2", "ScopeFlags"),
                    (0x0C, "int", "AttackProfile"),
                    (0x10, "u16x2", "KnockbackModeFlags"),
                    (0x14, "int", "ReactionMode"),
                    (0x18, "float", "Damage"),
                    (0x1C, "int", "LaunchProfile"),
                    (0x20, "int", "AttackProperty"),
                    (0x24, "u16x2", "BehaviorFlags"),
                )
                for field_rel, kind, field_name in attack_fields:
                    labels[start + field_rel] = (kind, f"{stem}.{field_name}")

    lookup_roots: list[tuple[int, str]] = []
    extra_roots: dict[str, list[tuple[int, str]]] = {}

    def structural_kind(rel: int) -> str:
        raw = u32(data, base + rel)
        if is_probable_string_id(strings, raw):
            return "string"
        if raw and raw % 4 == 0 and raw < size:
            return "ref"
        value = f32(data, base + rel)
        if math.isfinite(value) and 1.0e-6 <= abs(value) <= 100000.0:
            return "float"
        return "int"

    def annotate_fixed_records(
        table: str, start: int, count: int, stride: int, *, named: bool = False
    ) -> None:
        roots = extra_roots.setdefault(table, [])
        for index in range(count):
            record = start + index * stride
            record_name = string_value(strings, u32(data, base + record)) if named else ""
            suffix = clean_label(record_name) if record_name and not record_name.isdigit() else f"Record{index:03d}"
            stem = f"{table}.{suffix}"
            roots.append((record, stem))
            for field in range(0, stride, 4):
                rel = record + field
                field_name = "Name" if named and field == 0 and is_probable_string_id(strings, u32(data, base + rel)) else f"Field0x{field:02X}"
                labels[rel] = (structural_kind(rel), f"{stem}.{field_name}")
    lookup_tables = (
        ("BodyPartLookup", 0x180, 0x184, 0x188),
        ("HitLocationLookup", 0x18C, 0x190, 0x194),
    )
    for table_name, count_rel, data_rel, index_rel in lookup_tables:
        if index_rel + 4 > size:
            continue
        count = u32(data, base + count_rel)
        table_data = u32(data, base + data_rel)
        table_index = u32(data, base + index_rel)
        if not (0 < count < 0x1000 and 0 < table_data < table_index < size):
            continue
        if table_index + count * 4 > size:
            continue
        starts = [u32(data, base + table_index + index * 4) for index in range(count)]
        if any(not (table_data <= start < table_index) for start in starts):
            continue
        reserved_offsets.update(range(table_data, table_index))
        reserved_offsets.update(range(table_index, table_index + count * 4))
        for index, start in enumerate(starts):
            raw_name = u32(data, base + start)
            name = string_value(strings, raw_name)
            if not name:
                name = f"Entry{index:03d}"
            stem = f"{table_name}.{clean_label(name)}"
            lookup_roots.append((start, stem))
            labels[start] = ("string", f"{stem}.Name")

    collision_count = u32(data, base + 0x178) if size >= 0x180 else 0
    collision_start = u32(data, base + 0x17C) if size >= 0x180 else 0
    collision_end = u32(data, base + 0x1A0) if size >= 0x1A4 else 0
    if (
        0 < collision_count < 0x10000
        and 0 < collision_start < collision_end <= size
        and collision_start + collision_count * 0x30 == collision_end
    ):
        reserved_offsets.update(range(collision_start, collision_end))
        annotate_fixed_records("CollisionRecords", collision_start, collision_count, 0x30)

    action_tree_start = u32(data, base + 0x1A0) if size >= 0x1A4 else 0
    action_tree_end = u32(data, base + 0x1A8) if size >= 0x1AC else 0
    if 0 < action_tree_start < action_tree_end <= size:
        reserved_offsets.update(range(action_tree_start, action_tree_end))
        extra_roots["ActionTree"] = [(action_tree_start, "ActionTree")]
        for rel in range(action_tree_start, action_tree_end, 4):
            labels[rel] = ("u16x2", f"ActionTree.Packed.Word0x{rel - action_tree_start:04X}")

    weapon_count = u32(data, base + 0x1A4) if size >= 0x1AC else 0
    weapon_start = u32(data, base + 0x1A8) if size >= 0x1AC else 0
    transform_count = u32(data, base + 0x1AC) if size >= 0x1B8 else 0
    transform_start = u32(data, base + 0x1B0) if size >= 0x1B8 else 0
    transform_index = u32(data, base + 0x1B4) if size >= 0x1B8 else 0
    if 0 < weapon_count < 0x100 and weapon_start + weapon_count * 0x50 == transform_start:
        reserved_offsets.update(range(weapon_start, transform_start))
        roots = extra_roots.setdefault("MonsterWeapons", [])
        for index in range(weapon_count):
            record = weapon_start + index * 0x50
            record_name = string_value(strings, u32(data, base + record + 0x08))
            suffix = clean_label(record_name) if record_name and not record_name.isdigit() else f"Weapon{index:03d}"
            stem = f"MonsterWeapon.{suffix}"
            roots.append((record, stem))
            for field, kind, field_name in MONSTER_WEAPON_FIELDS:
                rel = record + field
                if kind == "string" and not is_probable_string_id(strings, u32(data, base + rel)):
                    kind = "int"
                labels[rel] = (kind, f"{stem}.{field_name}")
    if 0 < transform_count < 0x100 and 0 < transform_start < transform_index < size:
        starts = [u32(data, base + transform_index + index * 4) for index in range(transform_count)]
        if all(transform_start <= start < transform_index for start in starts):
            reserved_offsets.update(range(transform_start, transform_index + transform_count * 4))
            roots = extra_roots.setdefault("IndexedDataBlocks", [])
            for index, start in enumerate(starts):
                end = starts[index + 1] if index + 1 < len(starts) else transform_index
                stem = f"IndexedDataBlocks.Record{index:03d}"
                roots.append((start, stem))
                for rel in range(start, end - 3, 4):
                    labels[rel] = (structural_kind(rel), f"{stem}.Field0x{rel - start:03X}")

    effect_count = u32(data, base + 0x1B8) if size >= 0x1C0 else 0
    effect_start = u32(data, base + 0x1BC) if size >= 0x1C0 else 0
    if 0 < effect_count < 0x100 and effect_start + effect_count * 4 <= size:
        reserved_offsets.update(range(effect_start, effect_start + effect_count * 4))
        roots = extra_roots.setdefault("EffectResources", [])
        for index in range(effect_count):
            rel = effect_start + index * 4
            name = clean_label(string_value(strings, u32(data, base + rel)))
            stem = f"EffectResources.{name}"
            roots.append((rel, stem))
            labels[rel] = ("string", f"{stem}.Resource")

    ai_count = u32(data, base + 0x1C0) if size >= 0x1CC else 0
    ai_start = u32(data, base + 0x1C4) if size >= 0x1CC else 0
    ai_aux_start = u32(data, base + 0x1C8) if size >= 0x1CC else 0
    final_count = u32(data, base + 0x1CC) if size >= 0x1D4 else 0
    final_start = u32(data, base + 0x1D0) if size >= 0x1D4 else 0
    if 0 < ai_count < 0x100 and ai_start + ai_count * 0x1E0 == ai_aux_start:
        reserved_offsets.update(range(ai_start, ai_aux_start))
        annotate_fixed_records("AIProfiles", ai_start, ai_count, 0x1E0, named=True)
    if 0 < ai_aux_start < final_start <= size:
        reserved_offsets.update(range(ai_aux_start, final_start))
        roots = extra_roots.setdefault("AIAuxiliaryData", [(ai_aux_start, "AIAuxiliaryData")])
        for rel in range(ai_aux_start, final_start, 4):
            labels[rel] = (structural_kind(rel), f"AIAuxiliaryData.Field0x{rel - ai_aux_start:04X}")
    if 0 < final_count < 0x100 and 0 < final_start < size and (size - final_start) % final_count == 0:
        stride = (size - final_start) // final_count
        if stride and stride % 4 == 0:
            reserved_offsets.update(range(final_start, size))
            annotate_fixed_records("FinalTuning", final_start, final_count, stride)

    occupied = set(labels) | reserved_offsets
    for rel, label in scan_string_refs(data, strings, base, size, occupied).items():
        labels.setdefault(rel, ("string", label))
    occupied = set(labels) | reserved_offsets
    for rel, root in scan_pointer_refs(data, base, size, occupied, action_starts).items():
        raw = u32(data, base + rel)
        if root == "ActionRecordRef":
            labels.setdefault(rel, ("ref", f"Refs.{action_names.get(raw, f'Action0x{raw:06X}')}"))

    lines = [
        "# CMG MONSTER_DATA text export",
        f"# SourceCMG={bundle_path}",
        f"# MonsterData={character_data['name']}",
        f"# MonsterDataOffset=0x{base:X}",
        f"# MonsterDataSize=0x{size:X}",
        "# Format: @offset <type> <name> = <value>",
        "# Types: string, float, int, ref, u16x2, u8x4.",
        "# GameCube DAMM layout notes: big-endian; unnamed padding and unconfirmed fields are intentionally omitted.",
        "",
        "# Click on table names to view contents",
        "[RootTables.CoreTuning]",
        "@0x000000 CoreTuning",
        "",
        "[RootTables.ActionRecord]",
    ]
    for rel in action_starts:
        name = action_names[rel]
        lines.append(f"@0x{rel:06X} ActionRecord.{name}")
    lines.extend(["", "[RootTables.MoveEvents]"])
    for rel, stem in event_roots:
        lines.append(f"@0x{rel:06X} {stem}")
    lines.extend(["", "[RootTables.BodyPartLookup]"])
    for rel, stem in lookup_roots:
        if stem.startswith("BodyPartLookup."):
            lines.append(f"@0x{rel:06X} {stem}")
    lines.extend(["", "[RootTables.HitLocationLookup]"])
    for rel, stem in lookup_roots:
        if stem.startswith("HitLocationLookup."):
            lines.append(f"@0x{rel:06X} {stem}")
    if 0 < action_tree_start < action_tree_end <= size:
        lines.extend([
            "",
            "[RootTables.ActionTree]",
            f"@0x{action_tree_start:06X} ActionTree",
        ])
    for table_name in (
        "CollisionRecords", "MonsterWeapons", "IndexedDataBlocks",
        "EffectResources", "AIProfiles", "AIAuxiliaryData", "FinalTuning",
    ):
        roots = extra_roots.get(table_name, [])
        if not roots:
            continue
        lines.extend(["", f"[RootTables.{table_name}]"])
        for rel, stem in roots:
            lines.append(f"@0x{rel:06X} {stem}")
    lines.extend(["", "[MONSTER_DATA]"])

    previous_section = ""
    first_action_rel = min(action_starts, default=size)
    for rel in sorted(labels):
        kind, label = labels[rel]
        parts = label.split(".")
        if rel < first_action_rel:
            section = "CoreData"
        elif label.startswith("ActionRecord.") and len(parts) >= 2:
            section = ".".join(parts[:2])
        elif label.startswith("MoveEvent.") and len(parts) >= 3:
            section = ".".join(parts[:3])
        elif label.startswith("StringRefs."):
            section = "StringRefs"
        else:
            section = ".".join(parts[:2])
        if previous_section and section != previous_section and lines[-1] != "":
            lines.append("")
        if label.startswith("ActionRecord."):
            if rel in action_starts:
                record_name = action_names.get(rel, "")
                state = string_value(strings, u32(data, base + rel + 4))
                lines.append(f"## ActionRecord MONSTER_DATA+0x{rel:06X} {record_name} / {state}")
        previous_section = section
        value = row_value(data, strings, base + rel, kind)
        if kind == "ref":
            raw = u32(data, base + rel)
            if raw in action_names:
                value = f"ActionRecord.{action_names[raw]}"
        lines.append(f"@0x{rel:06X} {kind:<12} {label} = {value}")

    out_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"Wrote {out_path}")
    print(f"Exported {len(labels)} named CMG MONSTER_DATA values.")
    print(f"Annotated {len(action_starts)} action records.")


def parse_int_text(value: str) -> int:
    value = strip_inline_comment(value)
    if value.lower().startswith("0x"):
        return int(value, 16)
    return int(value, 10)


def parse_string_text(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] in "\"'" and value[-1] == value[0]:
        try:
            return str(ast.literal_eval(value))
        except Exception:
            return value[1:-1]
    value = strip_inline_comment(value).strip()
    return value


def parse_new_value(kind: str, value: str, strings: list[str], ref_lookup: dict[str, int] | None = None) -> bytes:
    if kind == "string":
        text = parse_string_text(value)
        if text in strings:
            return struct.pack(">I", strings.index(text))
        raise ValueError(f"String is not in this CMG string table: {text!r}")
    value = strip_inline_comment(value).strip()
    if kind == "float":
        return struct.pack(">f", float(value))
    if kind in {"int", "ref"}:
        if ref_lookup and value in ref_lookup:
            return struct.pack(">I", ref_lookup[value] & 0xFFFFFFFF)
        return struct.pack(">I", parse_int_text(value) & 0xFFFFFFFF)
    if kind == "u16x2":
        parts = [parse_int_text(part.strip()) for part in value.split(",")]
        if len(parts) != 2:
            raise ValueError("u16x2 values must be two comma-separated integers")
        return struct.pack(">HH", parts[0] & 0xFFFF, parts[1] & 0xFFFF)
    if kind == "u8x4":
        parts = [parse_int_text(part.strip()) for part in value.split(",")]
        if len(parts) != 4:
            raise ValueError("u8x4 values must be four comma-separated integers")
        return bytes(part & 0xFF for part in parts)
    raise ValueError(f"Unsupported type {kind}")


def build_ref_name_lookup_from_text(text: str) -> dict[str, int]:
    lookup = {}
    for line in text.splitlines():
        match = ROW_RE.match(line.strip())
        if match:
            lookup[match.group(3).strip()] = int(match.group(1), 16)
            continue
        if line.startswith("@0x"):
            parts = line.split(None, 2)
            if len(parts) >= 2:
                lookup[parts[-1].strip()] = int(parts[0][3:], 16)
    return lookup


def ref_value_name_counts_from_text(text: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for line in text.splitlines():
        match = ROW_RE.match(line.strip())
        if not match:
            continue
        if match.group(2) == "ref":
            value = strip_inline_comment(match.group(4)).strip()
            counts[value] = counts.get(value, 0) + 1
    return counts


def augment_ref_lookup_with_current_refs(text, data, base, size, ref_lookup):
    return ref_lookup


def import_txt(txt_path: Path, bundle_path: Path, out_path: Path) -> None:
    data, _parser, _entries, strings, character_data = parse_bundle(bundle_path)
    base, size = character_data_span(character_data)
    text = txt_path.read_text(encoding="utf-8")
    ref_lookup = build_ref_name_lookup_from_text(text)
    patches = 0
    for line in text.splitlines():
        match = ROW_RE.match(line.strip())
        if not match:
            continue
        rel = int(match.group(1), 16)
        kind = match.group(2)
        if rel < 0 or rel + 4 > size:
            raise ValueError(f"Offset 0x{rel:X} is outside MONSTER_DATA")
        new_bytes = parse_new_value(kind, match.group(4), strings, ref_lookup)
        if len(new_bytes) != 4:
            raise ValueError(f"{kind} at 0x{rel:X} did not compile to four bytes")
        data[base + rel:base + rel + 4] = new_bytes
        patches += 1

    out_path.write_bytes(data)
    BACKUP_ROOT.mkdir(exist_ok=True)
    backup_dir = BACKUP_ROOT / f"cmg_data_txt_import_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    backup_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy2(bundle_path, backup_dir / bundle_path.name)
    print(f"Wrote {out_path}")
    print(f"Patched {patches} CMG MONSTER_DATA values.")
    print(f"Backup: {backup_dir / bundle_path.name}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Export/import GameCube DAMM CMG MONSTER_DATA as editable text.")
    sub = parser.add_subparsers(dest="cmd", required=True)
    exp = sub.add_parser("export")
    exp.add_argument("bundle")
    exp.add_argument("out")
    imp = sub.add_parser("import")
    imp.add_argument("txt")
    imp.add_argument("bundle")
    imp.add_argument("out")
    args = parser.parse_args()
    if args.cmd == "export":
        export_txt(Path(args.bundle), Path(args.out))
    elif args.cmd == "import":
        import_txt(Path(args.txt), Path(args.bundle), Path(args.out))


if __name__ == "__main__":
    main()
