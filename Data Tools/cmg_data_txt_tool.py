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
    0x0D8: ("float", "CoreTuning.SpecialRange"),
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
    (0x0C, "float", "InputClass"),
    (0x10, "float", "ReactionLevel"),
    (0x14, "float", "DamageScale"),
    (0x18, "float", "HitDirectionX"),
    (0x1C, "float", "HitDirectionZ"),
    (0x20, "float", "FacingDirectionX"),
    (0x24, "float", "FacingDirectionZ"),
    (0x28, "float", "RootMotionX"),
    (0x2C, "float", "RootMotionZ"),
    (0x30, "u16x2", "InputButtonMask"),
    (0x34, "ref", "FollowupActionRef"),
    (0x38, "string", "ActionFamily"),
    (0x3C, "string", "Cue"),
    (0x40, "float", "StartFrame"),
    (0x44, "float", "ActiveFrame"),
    (0x48, "float", "RecoveryFrame"),
    (0x4C, "float", "CancelFrame"),
    (0x50, "float", "Priority"),
    (0x54, "float", "ComboWindow"),
    (0x58, "float", "RushWindow"),
    (0x5C, "float", "EnergyCost"),
    (0x60, "float", "ResourceFlags"),
]


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

    occupied = set(labels)
    for rel, label in scan_string_refs(data, strings, base, size, occupied).items():
        labels.setdefault(rel, ("string", label))
    occupied = set(labels)
    action_names = {
        rel: action_record_name(data, strings, base, rel, size) or f"Action0x{rel:06X}"
        for rel in action_starts
    }
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
        "[RootTables.TypeResistances]",
        "@0x000040 TypeResistances",
        "",
        "[RootTables.ActionRecord]",
    ]
    for rel in action_starts:
        name = action_names[rel]
        lines.append(f"@0x{rel:06X} ActionRecord.{name}")
    lines.extend(["", "[MONSTER_DATA]"])

    previous_section = ""
    for rel in sorted(labels):
        kind, label = labels[rel]
        section = label.split(".", 2)[0]
        if previous_section and section != previous_section and lines[-1] != "":
            lines.append("")
        if label.startswith("ActionRecord."):
            parts = label.split(".")
            section = ".".join(parts[:2])
            if section != previous_section and lines[-1] != "":
                lines.append("")
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
