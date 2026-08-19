#!/usr/bin/env python3
"""Export/import editable PS2 CLP LevelData rows."""

from __future__ import annotations

import argparse
import importlib.util
import re
import shutil
import struct
import sys
import zipfile
from datetime import datetime
from pathlib import Path
from tkinter import Tk, filedialog


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

TOOL_DIR = Path(__file__).resolve().parent
ROOT = TOOL_DIR.parent
BACKUP_ROOT = ROOT / "backups"
STAGE_DIR = ROOT / "CLP"
ENGINE_CANDIDATES = [
    ROOT / "Godzilla" / "STEM_113.54",
    ROOT / "isofixing" / "modded_vol_growth_1_stem" / "STEM_113.54",
    ROOT / "isofixing" / "stem" / "STEM_113.54",
]

ROW_RE = MD.ROW_RE
META_RE = MD.META_RE


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


def level_data_entries(entries: list[dict]) -> list[dict]:
    result: list[dict] = []
    for entry in entries:
        if entry.get("is_resource"):
            continue
        try:
            if int(entry.get("file_type", -1)) != 2:
                continue
        except Exception:
            continue
        name = str(entry.get("name", "")).replace("\\", "/")
        base_name = Path(name).name.lower()
        if base_name == "leveldata" or re.match(r"^\d{3}leveldata$", base_name):
            result.append(entry)
    return result


def choose_level_data_entry(entries: list[dict], entry_name: str | None = None) -> dict:
    candidates = level_data_entries(entries)
    if not candidates:
        raise RuntimeError("CLP has no type-2 LevelData entry")
    if entry_name:
        wanted = entry_name.replace("\\", "/").lower()
        for entry in candidates:
            name = str(entry.get("name", "")).replace("\\", "/").lower()
            if wanted == name or wanted in name:
                return entry
        raise RuntimeError(f"No LevelData entry matched {entry_name!r}")
    preferred = next(
        (entry for entry in candidates if Path(str(entry.get("name", ""))).name.lower() in {"001leveldata", "leveldata"}),
        None,
    )
    return preferred or candidates[0]


def parse_bundle(bundle_path: Path, entry_name: str | None = None):
    data = bytearray(bundle_path.read_bytes())
    parser = MD.PipeworksParser(bundle_path)
    entries = parser.parse_from_data(bytes(data))
    strings = parser.read_strings()
    level_data = choose_level_data_entry(entries, entry_name)
    level_data["endian"] = getattr(parser, "endian", "<") or "<"
    return data, parser, entries, strings, level_data


def character_data_span(entry: dict) -> tuple[int, int]:
    return int(entry.get("data_offset", entry.get("offset", 0))), int(entry.get("data_size", entry.get("size", 0)))


level_data_span = character_data_span


def clean_label(value: str) -> str:
    return MD.clean_label(value).strip("_") or "Value"


def strip_level_section_prefix(value: str) -> str:
    return re.sub(r"^00[0-9](?=[A-Za-z_#])", "", value)


def level_value_stem(value: str) -> str:
    stripped = strip_level_section_prefix(MD.strip_ps2_prefix(MD.cstr_safe(value)))
    return clean_label(stripped)


def level_display_name(value: str) -> str:
    stripped = strip_level_section_prefix(MD.strip_ps2_prefix(MD.cstr_safe(value)))
    return stripped.replace("_", " ").strip() or "Value"


def load_engine_level_terms() -> set[str]:
    terms: set[str] = set()
    for path in ENGINE_CANDIDATES:
        if not path.exists():
            continue
        data = path.read_bytes()
        for match in re.finditer(rb"[ -~]{4,}", data):
            text = match.group(0).decode("ascii", "ignore").strip()
            if (
                text.startswith("LevelDBObjClass_")
                or text.endswith("Fixup")
                or text in {"LevelData", "ActivationRange", "OnLoadLevelData", "loadLevelData"}
            ):
                terms.add(text)
                if text.startswith("LevelDBObjClass_"):
                    terms.add(text.split("_", 1)[1])
    return terms


ENGINE_LEVEL_TERMS = load_engine_level_terms()


STRING_FIELD_NAMES = {
    "name",
    "type",
    "nodename",
    "shapename",
    "soundname",
    "collapsesound",
    "damagedsound",
    "finissectionname",
    "resourcename",
    "runtimeclass",
    "weapon0_name",
    "weapon_0",
    "weapon0",
    "hittexturename",
    "hiteffectname",
    "one-timehiteffectname",
    "onetimehiteffectname",
    "rigidexplodeeffect",
    "rigidtumbledeatheffect",
    "destructioneffect",
    "defaultwalkthrough",
    "default walkthrough",
    "collisionprimitive",
    "collisionshape",
    "dayrubbleshape",
    "rubbleshape",
    "dayshape",
    "night_shape",
    "daytimeoverrideshape",
    "texture_name",
    "texturename",
    "texturename0",
    "texturename1",
    "path",
    "defaultroute",
    "instancenotifyfuncname",
}


FLOAT_FIELD_NAMES = {
    "x",
    "y",
    "z",
    "point_x",
    "point_y",
    "point_z",
    "matrix_00",
    "matrix_01",
    "matrix_02",
    "matrix_10",
    "matrix_11",
    "matrix_12",
    "matrix_20",
    "matrix_21",
    "matrix_22",
    "width",
    "height",
    "depth",
    "mass",
    "elasticity",
    "friction",
    "activationrange",
    "deactivationrange",
    "rotationrange",
    "elevationrange",
    "maximumspeed",
    "stopspeed",
    "stopthreshold",
    "impactdamage",
    "rigiddmgmul",
    "rigidhitpoints",
    "tumblingdeathduration",
    "fadeoutduration",
    "nearplane",
    "farplane",
    "defaultbias",
    "defaultcontinuity",
    "defaulttension",
    "medianwidth",
    "lanes",
}


INT_FIELD_NAMES = {
    "flags",
    "loadflag",
    "renderflag",
    "collideflag",
    "closedflag",
    "edgetriggerflag",
    "dumpflag",
    "finisflag",
    "oneshot",
    "autactivation",
    "autoactivation",
    "startinactiveflag",
    "triggeronplayerflag",
    "triggeronenemyflag",
    "interiortriggerflag",
    "canbejumpedoverflag",
    "hitpoints",
    "rigidconversion",
    "throwtype",
    "weapontype",
    "eventindex",
    "eventtype",
    "regiontype",
    "numais",
}


def normalized_name(value: str) -> str:
    return level_display_name(value).replace(" ", "").replace("-", "").replace("_", "").lower()


def is_level_record_type(value: str) -> bool:
    clean = level_display_name(value)
    return (
        clean.endswith("Fixup")
        or clean in {"LevelData", "SectionData"}
    )


PROPERTY_GROUP_NAMES = {
    "advanceddamage",
    "ai",
    "xform",
    "xform3",
    "event",
    "activationrange",
    "deactivationrange",
    "autorotation",
    "autactivation",
    "autoactivation",
    "rotation_control",
    "elevation_control",
    "collisiondimensions",
    "collisionoffset",
    "collisionprimitive",
    "collisionshape",
    "fluffeffectfixup",
    "fluffinstancefixup",
    "flufftemplatefixup",
    "buildingtemplatefixup",
    "buildinginstancefixup",
    "objecttemplatefixup",
    "objectinstancefixup",
    "transforminstancefixup",
    "nodeinstancefixup",
    "pathfixup",
    "regiontemplatefixup",
    "subboundaryfixup",
    "aigroupinstancefixup",
    "aigrouptemplatefixup",
    "sectiondata",
    "sectiontemplatefixup",
}


def is_property_group(value: str) -> bool:
    clean = level_display_name(value)
    norm = normalized_name(clean)
    if clean == "#ZBias":
        return False
    return norm in {normalized_name(item) for item in PROPERTY_GROUP_NAMES} or clean.endswith("Fixup")


def table_name_for_type(record_type: str) -> str:
    clean = level_display_name(record_type)
    if clean.endswith("Fixup"):
        clean = clean[: -len("Fixup")]
    clean = clean.replace("LevelDBObjClass ", "")
    stem = clean_label(clean)
    if stem.endswith("Instance"):
        return stem + "s"
    if stem.endswith("Template"):
        return stem + "s"
    if stem.endswith("Data"):
        return stem
    return stem or "LevelData"


def endian_prefix(endian: str | None) -> str:
    return ">" if endian == ">" else "<"


def endian_byteorder(endian: str | None) -> str:
    return "big" if endian == ">" else "little"


def u32e(data: bytes | bytearray, offset: int, endian: str | None = "<") -> int:
    return struct.unpack_from(f"{endian_prefix(endian)}I", data, offset)[0]


def f32e(data: bytes | bytearray, offset: int, endian: str | None = "<") -> float:
    return struct.unpack_from(f"{endian_prefix(endian)}f", data, offset)[0]


def signed32(value: int) -> int:
    return value if value < 0x80000000 else value - 0x100000000


def u16x2_text(raw: int, endian: str | None = "<") -> str:
    if endian == ">":
        return f"{(raw >> 16) & 0xFFFF}, {raw & 0xFFFF}"
    return f"{raw & 0xFFFF}, {(raw >> 16) & 0xFFFF}"


def string_value(data: bytes | bytearray, strings: list[str], absolute: int, endian: str | None = "<") -> str:
    index = u32e(data, absolute, endian)
    if 0 <= index < len(strings):
        return MD.cstr_safe(strings[index])
    return str(index)


def parse_string_index(value: str, strings: list[str]) -> int:
    value = value.strip()
    if value in strings:
        return strings.index(value)
    prefixed = "000" + value
    if prefixed in strings:
        return strings.index(prefixed)
    wanted = MD.cstr_safe(value)
    for index, text in enumerate(strings):
        if MD.cstr_safe(text) == wanted:
            return index
    wanted_display = level_display_name(value)
    for index, text in enumerate(strings):
        if level_display_name(MD.cstr_safe(text)) == wanted_display:
            return index
    return int(value, 0)


def row_value(data: bytes | bytearray, strings: list[str], absolute: int, kind: str, endian: str | None = "<") -> str:
    raw = u32e(data, absolute, endian)
    if kind == "string":
        return string_value(data, strings, absolute, endian)
    if kind in {"f32", "float"}:
        return repr(float(f32e(data, absolute, endian)))
    if kind in {"u32", "word", "int", "ref"}:
        return f"0x{raw:08X}"
    if kind == "bool":
        return "true" if raw else "false"
    if kind == "u16x2":
        return u16x2_text(raw, endian)
    if kind == "u8x4":
        return MD.u8x4_text(raw)
    raise ValueError(kind)


def export_row_type_and_value(
    data: bytes | bytearray,
    strings: list[str],
    absolute_offset: int,
    force: str | None = None,
    endian: str | None = "<",
) -> tuple[str, str]:
    raw = u32e(data, absolute_offset, endian)
    if force == "string":
        return "string", string_value(data, strings, absolute_offset, endian)
    if force == "f32":
        return "float", repr(float(f32e(data, absolute_offset, endian)))
    if force == "u16x2":
        return "u16x2", u16x2_text(raw, endian)
    if force == "u8x4":
        return "u8x4", MD.u8x4_text(raw)
    if force == "ref":
        return "ref", str(signed32(raw))
    if force == "bool":
        return "bool", "true" if raw else "false"
    if force == "int":
        return "int", str(signed32(raw))

    if raw != 0 and 0 <= raw < len(strings) and strings[raw]:
        return "string", string_value(data, strings, absolute_offset, endian)
    if MD.looks_like_u16x2(raw):
        return "u16x2", u16x2_text(raw, endian)
    if MD.looks_like_u8x4(raw):
        return "u8x4", MD.u8x4_text(raw)

    value = f32e(data, absolute_offset, endian)
    exponent = (raw >> 23) & 0xFF
    if raw != 0 and 0x70 <= exponent <= 0x8E and abs(value) < 1000000.0:
        return "float", repr(float(value))
    return "int", str(signed32(raw))


def parse_new_value(kind: str, value: str, strings: list[str], ref_lookup: dict[str, int] | None = None, endian: str | None = "<") -> bytes:
    value = MD.strip_inline_comment(value)
    ascii_size = MD.parse_ascii_kind(kind)
    if ascii_size is not None:
        return MD.ascii_bytes_for_field(value, ascii_size)
    order = endian_byteorder(endian)
    if kind in {"word", "int", "ref"}:
        if value.lower().startswith("f:"):
            return struct.pack(f"{endian_prefix(endian)}f", float(value[2:].strip()))
        if value.lower().startswith("s:"):
            return parse_string_index(value[2:].strip(), strings).to_bytes(4, order)
        if kind == "ref" and ref_lookup is not None:
            try:
                return MD.parse_u32_value(value).to_bytes(4, order)
            except ValueError:
                key = MD.ref_lookup_key(value)
                if key in ref_lookup:
                    return int(ref_lookup[key]).to_bytes(4, order)
                raise
        return MD.parse_u32_value(value).to_bytes(4, order)
    if kind == "string":
        if value.lower().startswith("s:"):
            value = value[2:].strip()
        return parse_string_index(value, strings).to_bytes(4, order)
    if kind == "u32":
        return MD.parse_u32_value(value).to_bytes(4, order)
    if kind == "bool":
        normalized = value.strip().lower()
        if normalized in {"true", "yes", "on", "1"}:
            return (1).to_bytes(4, order)
        if normalized in {"false", "no", "off", "0"}:
            return (0).to_bytes(4, order)
        raise ValueError(f"bool value must be true/false or 1/0: {value}")
    if kind in {"f32", "float"}:
        raw = value[2:].strip() if value.lower().startswith("f:") else value.strip()
        return struct.pack(f"{endian_prefix(endian)}f", float(raw))
    if kind == "u16x2":
        parts = [part.strip() for part in value.split(",")]
        if len(parts) != 2:
            raise ValueError(f"u16x2 needs two comma-separated values: {value}")
        first, second = (int(part, 0) & 0xFFFF for part in parts)
        raw = ((first << 16) | second) if endian == ">" else ((second << 16) | first)
        return raw.to_bytes(4, order)
    if kind == "u8x4":
        parts = [part.strip() for part in value.split(",")]
        if len(parts) != 4:
            raise ValueError(f"u8x4 needs four comma-separated values: {value}")
        return bytes(int(part, 0) & 0xFF for part in parts)
    raise ValueError(f"Unsupported row kind {kind}")


def row_string(data: bytes | bytearray, strings: list[str], absolute: int, endian: str | None = "<") -> str | None:
    raw = u32e(data, absolute, endian)
    if 0 <= raw < len(strings):
        return strings[raw]
    return None


def row_string_clean(data: bytes | bytearray, strings: list[str], absolute: int, endian: str | None = "<") -> str | None:
    value = row_string(data, strings, absolute, endian)
    if value is None:
        return None
    cleaned = level_display_name(value)
    if not cleaned or cleaned == "Value" or re.fullmatch(r"00[0-9]", cleaned):
        return None
    return cleaned


def looks_like_record_header(next_raw: int) -> bool:
    # Level DB fixup records use a packed header/count word after the record type.
    return ((next_raw >> 16) != 0) and (1 <= (next_raw & 0xFFFF) <= 0x100)


def find_level_records(data: bytes | bytearray, strings: list[str], base: int, size: int, endian: str | None = "<") -> list[dict[str, object]]:
    records: list[dict[str, object]] = []
    for rel in range(0, size - 8, 4):
        record_type = row_string_clean(data, strings, base + rel, endian)
        if not record_type or not is_level_record_type(record_type):
            if record_type == "#ZBias":
                name = row_string_clean(data, strings, base + rel + 4, endian)
                group = row_string_clean(data, strings, base + rel + 8, endian)
                if name and name != "#ZBias" and group and not is_property_group(name) and is_property_group(group):
                    records.append({"start": rel, "type": "RootObject", "table": "RootObjects", "name": clean_label(name)})
            continue
        next_raw = u32e(data, base + rel + 4, endian)
        if rel != 0x0C and not looks_like_record_header(next_raw):
            continue
        table = table_name_for_type(record_type)
        record_name = ""
        for probe in range(rel + 8, min(rel + 0x30, size - 3), 4):
            candidate = row_string_clean(data, strings, base + probe, endian)
            if not candidate:
                continue
            norm = normalized_name(candidate)
            if norm in {"name", "type"} or norm.isdigit() or is_level_record_type(candidate):
                continue
            record_name = candidate
            break
        if not record_name:
            if table == "LevelTemplates":
                record_name = "LevelTemplate"
            elif table == "SectionTemplates":
                record_name = "SectionTemplate"
            else:
                record_name = f"{table}_{len(records):03d}"
        records.append({"start": rel, "type": record_type, "table": table, "name": clean_label(record_name)})
    records.sort(key=lambda item: int(item["start"]))
    first_real_record = min(
        (
            int(record["start"])
            for record in records
            if record.get("type") != "RootObject" and record.get("table") != "SectionTemplates"
        ),
        default=size,
    )
    filtered: list[dict[str, object]] = []
    for record in records:
        if record.get("type") == "RootObject":
            if int(record["start"]) >= first_real_record:
                continue
            previous = filtered[-1] if filtered else None
            if previous and previous.get("table") != "SectionTemplates" and int(record["start"]) - int(previous["start"]) < 0x300:
                continue
        filtered.append(record)
    records = filtered
    for index, record in enumerate(records):
        record["end"] = int(records[index + 1]["start"]) if index + 1 < len(records) else size
    return records


def force_for_property(field_name: str, raw: int, size: int, endian: str | None = "<") -> str | None:
    norm = normalized_name(field_name)
    if norm in STRING_FIELD_NAMES or norm.endswith("name") or norm.endswith("shape") or norm.endswith("sound"):
        return "string"
    if raw % 4 == 0 and 0x20 <= raw < size and not (norm.startswith("matrix") or norm.startswith("point")):
        return "ref"
    if norm in FLOAT_FIELD_NAMES or norm.startswith("matrix") or norm.startswith("point"):
        return "f32"
    if norm in INT_FIELD_NAMES or norm.endswith("flag") or norm.endswith("flags"):
        return "int"
    if raw != 0:
        exponent = (raw >> 23) & 0xFF
        if 0x70 <= exponent <= 0x8E:
            value = abs(struct.unpack(f"{endian_prefix(endian)}f", raw.to_bytes(4, endian_byteorder(endian)))[0])
            if value is not None and value < 1000000.0:
                return "f32"
    return None


def record_stem(record: dict[str, object]) -> str:
    # Editable names should be the actual placed/template object name. The
    # LevelDB class bucket (FluffInstances, BuildingTemplates, etc.) stays in
    # RootTables/comments only.
    return str(record["name"])


def wii_entry_table_name(record_type: str) -> str:
    clean = level_display_name(record_type)
    if clean.endswith("Fixup"):
        clean = clean[: -len("Fixup")]
    clean = clean.replace("FluffObject", "Object")
    clean = clean.replace("Fluff", "")
    clean = clean_label(clean)
    if clean.endswith("Instance") or clean.endswith("Template"):
        return clean + "s"
    return clean or "LevelDB"


def parse_wii_leveldb_entries(
    data: bytes | bytearray,
    strings: list[str],
    base: int,
    size: int,
) -> list[dict[str, object]]:
    if size < 0x20:
        return []
    count = u32e(data, base + 0x08, ">")
    table_off = u32e(data, base + 0x0C, ">")
    if count <= 0 or count > 20000 or table_off >= size or table_off % 4:
        return []

    entries: list[dict[str, object]] = []
    rel = table_off
    for index in range(count):
        if rel + 0x10 > size:
            break
        type_index = u32e(data, base + rel, ">")
        word_count = u32e(data, base + rel + 0x08, ">")
        name_index = u32e(data, base + rel + 0x0C, ">")
        if word_count <= 0 or rel + word_count * 4 > size:
            break
        record_type = strings[type_index] if 0 <= type_index < len(strings) else f"Type{type_index:04X}"
        name = strings[name_index] if 0 <= name_index < len(strings) else f"Entry{index:04d}"
        table = wii_entry_table_name(record_type)
        entries.append(
            {
                "index": index,
                "start": rel,
                "end": rel + word_count * 4,
                "word_count": word_count,
                "type": record_type,
                "table": table,
                "name": clean_label(level_display_name(name)),
                "display_name": level_display_name(name),
            }
        )
        rel += word_count * 4
    return entries


def wii_entry_at(entries: list[dict[str, object]], offset: int) -> dict[str, object] | None:
    for entry in entries:
        if int(entry["start"]) == offset:
            return entry
    return None


def collect_wii_leveldb_rows(
    data: bytes | bytearray,
    strings: list[str],
    base: int,
    size: int,
) -> tuple[list[dict[str, object]], dict[int, tuple[str, str]], list[str]]:
    entries = parse_wii_leveldb_entries(data, strings, base, size)
    rows: dict[int, tuple[str, str]] = {
        0x04: ("int", "WiiLevelDB.Header.ByteSize"),
        0x08: ("int", "WiiLevelDB.Header.EntryCount"),
        0x0C: ("ref", "WiiLevelDB.Header.EntryTableOffset"),
        0x10: ("ref", "WiiLevelDB.Header.NameLookupOffset"),
    }
    if entries:
        level_entry = entries[0]
        if str(level_entry.get("type")) == "LevelTemplateFixup":
            rows.update(
                {
                    0x20: ("string", "WiiLevelDB.LevelTemplate.EntryType"),
                    0x24: ("int", "WiiLevelDB.LevelTemplate.EntryFlags"),
                    0x28: ("int", "WiiLevelDB.LevelTemplate.WordCount"),
                    0x2C: ("string", "WiiLevelDB.LevelTemplate.Name"),
                    0x40: ("string", "Stage.Name"),
                    0x44: ("string", "Stage.TerrainResource"),
                    0x48: ("string", "Stage.LightsPRX"),
                    0x4C: ("string", "Stage.CubeMapSource"),
                    0x50: ("string", "Stage.SpawnManager"),
                    0x54: ("string", "Stage.CityLightsTexture"),
                    0x8C: ("string", "Stage.SkyboxResource"),
                    0x90: ("string", "Stage.CloudRingOuterResource"),
                    0x94: ("string", "Stage.CloudRingInnerResource"),
                    0x98: ("string", "Stage.SpawnManager2"),
                }
            )

    entry_starts = {int(entry["start"]) for entry in entries}
    for entry in entries[1:]:
        start = int(entry["start"])
        end = int(entry["end"])
        stem = str(entry["name"])
        rows[start] = ("string", f"{stem}.EntryType")
        rows[start + 0x04] = ("int", f"{stem}.EntryFlags")
        rows[start + 0x0C] = ("string", f"{stem}.Name")
        if start + 0x24 < end:
            target = u32e(data, base + start + 0x24, ">")
            if target in entry_starts or target == 0:
                rows[start + 0x24] = ("ref", f"{stem}.TemplateEntryRef")
        if start + 0x6C <= end:
            matrix = [f32e(data, base + start + 0x30 + index * 4, ">") for index in range(9)]
            point = [f32e(data, base + start + 0x60 + index * 4, ">") for index in range(3)]
            if any(abs(value) > 0.0001 for value in matrix) and all(abs(value) <= 1.001 for value in matrix):
                for index, field in enumerate(MATRIX_FIELDS):
                    rows[start + 0x30 + index * 4] = ("f32", f"{stem}.Transform.{field}")
                for index, axis in enumerate("XYZ"):
                    rows[start + 0x60 + index * 4] = ("f32", f"{stem}.Transform.Position_{axis}")

    if entries:
        first_end = int(entries[0]["end"])
        float_runs: list[tuple[int, int, int]] = []
        run: list[int] = []
        for rel in range(0x100, min(first_end, size - 3), 4):
            raw = u32e(data, base + rel, ">")
            value = f32e(data, base + rel, ">")
            exponent = (raw >> 23) & 0xFF
            looks_float = raw != 0 and 0x70 <= exponent <= 0x8E and abs(value) < 1000000.0
            if looks_float:
                run.append(rel)
            else:
                if len(run) >= 90 and len(run) % 3 == 0:
                    float_runs.append((run[0], run[-1] + 4, len(run)))
                run = []
        if len(run) >= 90 and len(run) % 3 == 0:
            float_runs.append((run[0], run[-1] + 4, len(run)))
        for run_index, (start, _end, count) in enumerate(float_runs):
            table = "VertexPositions" if run_index == 0 else f"FloatTriples{run_index:02d}"
            for word_index in range(count):
                rel = start + word_index * 4
                vertex_index = word_index // 3
                axis = "XYZ"[word_index % 3]
                rows.setdefault(rel, ("f32", f"SectionGeometry.{table}.Vertex{vertex_index:04d}.{axis}"))

    toc_lines: list[str] = ["# Click on table names to view contents", "[RootTables.WiiLevelDB]"]
    toc_lines.append("@0x000000 Header")
    if entries:
        toc_lines.append(f"@0x{int(entries[0]['start']):06X} LevelTemplate")
    toc_lines.append("")
    by_table: dict[str, list[dict[str, object]]] = {}
    for entry in entries[1:]:
        by_table.setdefault(str(entry["table"]), []).append(entry)
    for table in sorted(by_table):
        toc_lines.append(f"[RootTables.{table}]")
        for entry in by_table[table]:
            toc_lines.append(f"@0x{int(entry['start']):06X} {entry['display_name']}")
        toc_lines.append("")
    if any(label.startswith("SectionGeometry.") for _force, label in rows.values()):
        toc_lines.append("[RootTables.SectionGeometry]")
        toc_lines.append("@0x000100 Vertex/packed geometry ranges")
        toc_lines.append("")
    return entries, rows, toc_lines


MATRIX_FIELDS = (
    "Matrix_00",
    "Matrix_01",
    "Matrix_02",
    "Matrix_10",
    "Matrix_11",
    "Matrix_12",
    "Matrix_20",
    "Matrix_21",
    "Matrix_22",
)


def looks_like_direct_xform(data: bytes | bytearray, base: int, start: int, end: int, size: int, endian: str | None = "<") -> bool:
    if start + 0x54 > end or start + 0x54 > size:
        return False
    matrix_values = [f32e(data, base + start + 0x24 + index * 4, endian) for index in range(9)]
    if any(abs(value) > 1.01 for value in matrix_values):
        return False
    if not any(abs(value) > 0.001 for value in matrix_values):
        return False
    point_values = [f32e(data, base + start + 0x48 + index * 4, endian) for index in range(3)]
    return any(abs(value) > 0.001 for value in point_values)


def is_property_field(group: str, field: str) -> bool:
    if level_display_name(group).endswith("Fixup"):
        return True
    norm = normalized_name(field)
    if norm in STRING_FIELD_NAMES or norm in FLOAT_FIELD_NAMES or norm in INT_FIELD_NAMES:
        return True
    if norm.startswith("matrix") or norm.startswith("point"):
        return True
    if norm.endswith("name") or norm.endswith("flag") or norm.endswith("flags"):
        return True
    if norm in {normalized_name(item) for item in PROPERTY_GROUP_NAMES}:
        return True
    return False


def embedded_name_before(
    data: bytes | bytearray,
    strings: list[str],
    base: int,
    record_start: int,
    rel: int,
    endian: str | None = "<",
) -> str | None:
    search_start = max(record_start, rel - 0x120)
    for probe in range(rel - 4, search_start - 1, -4):
        field = row_string_clean(data, strings, base + probe, endian)
        if not field or normalized_name(field) != "name":
            continue
        value = row_string_clean(data, strings, base + probe + 4, endian)
        if not value:
            continue
        value_norm = normalized_name(value)
        if value_norm in {"xform", "xform3", "name", "type"} or is_property_group(value):
            continue
        return clean_label(value)
    return None


def collect_structured_level_rows(
    data: bytes | bytearray,
    strings: list[str],
    base: int,
    size: int,
    endian: str | None = "<",
) -> tuple[list[dict[str, object]], dict[int, tuple[str, str]], list[str]]:
    if endian == ">":
        return collect_wii_leveldb_rows(data, strings, base, size)

    records = find_level_records(data, strings, base, size, endian)
    rows: dict[int, tuple[str, str]] = {
        0x00: ("int", "LevelData.Header.FormatVersion"),
        0x04: ("int", "LevelData.Header.ByteSize"),
    }
    if size >= 0x0C:
        rows[0x08] = ("string", "LevelData.Header.RootResource")
    if endian == ">":
        rows.update(
            {
                0x00: ("string", "WiiLevelData.Header.FirstName"),
                0x04: ("int", "WiiLevelData.Header.ByteSize"),
                0x08: ("string", "WiiLevelData.Header.FirstSpawnPoint"),
                0x0C: ("string", "WiiLevelData.Header.CameraManager"),
                0x10: ("ref", "WiiLevelData.Header.ObjectDirectoryRef"),
                0x20: ("string", "WiiLevelData.Header.LevelTemplateType"),
                0x24: ("string", "WiiLevelData.Header.InstanceScalingField"),
                0x28: ("ref", "WiiLevelData.Header.TemplateDirectoryRef"),
                0x2C: ("string", "WiiLevelData.Header.ResourceType"),
                0x40: ("string", "WiiLevelData.Stage.Name"),
                0x44: ("string", "WiiLevelData.Stage.TerrainResource"),
                0x48: ("string", "WiiLevelData.Stage.LightsPRX"),
                0x4C: ("string", "WiiLevelData.Stage.CubeMapSource"),
                0x50: ("string", "WiiLevelData.Stage.SpawnManager"),
                0x54: ("string", "WiiLevelData.Stage.CityLightsTexture"),
                0x8C: ("string", "WiiLevelData.Stage.SkyboxResource"),
                0x90: ("string", "WiiLevelData.Stage.CloudRingOuterResource"),
                0x94: ("string", "WiiLevelData.Stage.CloudRingInnerResource"),
                0x98: ("string", "WiiLevelData.Stage.SpawnManager2"),
                0xDC: ("string", "WiiLevelData.Header.TriggerCountField"),
            }
        )
    if size >= 0x9C:
        section_header_fields = {
            0x14: ("string", "SectionTemplate.DataType"),
            0x18: ("ref", "SectionTemplate.PackedSectionDataRef"),
            0x24: ("ref", "SectionTemplate.Geometry.ByteTableRef"),
            0x60: ("string", "SectionTemplate.RootObjectName"),
            0x64: ("string", "SectionTemplate.ShapeResource"),
            0x68: ("ref", "SectionTemplate.Geometry.ByteTableRef2"),
            0x6C: ("string", "SectionTemplate.ShapeNodeName"),
            0x70: ("string", "SectionTemplate.DamageMaterial"),
            0x74: ("ref", "SectionTemplate.Geometry.BlockARef"),
            0x78: ("ref", "SectionTemplate.Geometry.BlockBRef"),
            0x7C: ("f32", "SectionTemplate.Bounds.CenterX"),
            0x80: ("f32", "SectionTemplate.Bounds.CenterY"),
            0x84: ("f32", "SectionTemplate.Bounds.CenterZ"),
            0x88: ("f32", "SectionTemplate.Bounds.Radius"),
            0x8C: ("string", "SectionTemplate.BaseMaterial"),
            0x90: ("f32", "SectionTemplate.MaterialBlendA"),
            0x94: ("f32", "SectionTemplate.MaterialBlendB"),
            0x98: ("ref", "SectionTemplate.Geometry.ByteTableRef3"),
        }
        rows.update(section_header_fields)

    first_record_start = min((int(record["start"]) for record in records if int(record["start"]) > 0x100), default=size)
    float_runs: list[tuple[int, int, int]] = []
    run: list[int] = []
    for rel in range(0x100, first_record_start, 4):
        raw = u32e(data, base + rel, endian)
        value = f32e(data, base + rel, endian)
        exponent = (raw >> 23) & 0xFF
        looks_float = raw != 0 and 0x70 <= exponent <= 0x8E and abs(value) < 1000000.0
        if looks_float:
            run.append(rel)
        else:
            if len(run) >= 90 and len(run) % 3 == 0:
                float_runs.append((run[0], run[-1] + 4, len(run)))
            run = []
    if len(run) >= 90 and len(run) % 3 == 0:
        float_runs.append((run[0], run[-1] + 4, len(run)))
    for run_index, (start, _end, count) in enumerate(float_runs):
        table = "VertexPositions" if run_index == 0 else f"FloatTriples{run_index:02d}"
        for word_index in range(count):
            rel = start + word_index * 4
            vertex_index = word_index // 3
            axis = "XYZ"[word_index % 3]
            rows[rel] = ("f32", f"SectionGeometry.{table}.Vertex{vertex_index:04d}.{axis}")

    for record in records:
        start = int(record["start"])
        end = int(record["end"])
        stem = record_stem(record)
        rows[start] = ("string", f"{stem}.RecordType")
        name_rel = None
        for probe in range(start + 8, min(start + 0x30, end, size - 3), 4):
            candidate = row_string_clean(data, strings, base + probe, endian)
            if candidate and clean_label(candidate) == record["name"]:
                name_rel = probe
                break
        if name_rel is not None:
            rows[name_rel] = ("string", f"{stem}.Name")

        table_name = str(record.get("table", ""))
        if table_name.endswith("Instances") and looks_like_direct_xform(data, base, start, end, size, endian):
            for index, field in enumerate(MATRIX_FIELDS):
                rows.setdefault(start + 0x24 + index * 4, ("f32", f"{stem}.XForm.{field}"))
            for index, axis in enumerate("XYZ"):
                rows.setdefault(start + 0x48 + index * 4, ("f32", f"{stem}.XForm.Point_{axis}"))

        rel = start + 8
        while rel + 8 < end and rel + 8 < size:
            group = row_string_clean(data, strings, base + rel, endian)
            field = row_string_clean(data, strings, base + rel + 4, endian)
            if group and field:
                if stem == "Value" and normalized_name(field).endswith("fixup"):
                    rel += 4
                    continue
                group_label = group
                field_norm = normalized_name(field)
                group_is_transform_placeholder = group == "#ZBias" and (
                    field_norm.startswith("matrix") or field_norm.startswith("point")
                )
                if group_is_transform_placeholder:
                    group_label = "ActivationRange"
                if not ((is_property_group(group) and is_property_field(group, field)) or group_is_transform_placeholder):
                    rel += 4
                    continue
                value_rel = rel + 8
                raw = u32e(data, base + value_rel, endian)
                force = force_for_property(field, raw, size, endian)
                if force is None and raw != 0 and 0 <= raw < len(strings):
                    force = "string"
                if force is None:
                    force = "int"
                label_stem = stem
                if group_is_transform_placeholder and stem == "Value":
                    label_stem = embedded_name_before(data, strings, base, start, rel, endian) or stem
                label = f"{label_stem}.{clean_label(group_label)}.{clean_label(field)}"
                rows[value_rel] = (force, label)
                rel += 12
                continue
            rel += 4

    if endian == ">":
        for rel in range(0, size - 3, 4):
            if rel in rows:
                continue
            raw = u32e(data, base + rel, endian)
            if not (0 <= raw < len(strings)):
                continue
            text = MD.cstr_safe(strings[raw])
            if not text or text == "#ZBias" or re.fullmatch(r"00[0-9]", text):
                continue
            rows[rel] = ("string", f"WiiLevelRefs.{clean_label(level_display_name(text))}")

    toc_lines: list[str] = ["# Click on table names to view contents"]
    by_table: dict[str, list[dict[str, object]]] = {}
    for record in records:
        by_table.setdefault(str(record["table"]), []).append(record)
    toc_lines.append("[RootTables.LevelData]")
    toc_lines.append("@0x000000 Header")
    toc_lines.append("")
    section_data_ref = u32e(data, base + 0x18, endian) if size >= 0x1C else 0
    block_a_ref = u32e(data, base + 0x74, endian) if size >= 0x78 else 0
    block_b_ref = u32e(data, base + 0x78, endian) if size >= 0x7C else 0
    byte_table_ref = u32e(data, base + 0x68, endian) if size >= 0x6C else 0
    section_refs = [
        (section_data_ref, "PackedSectionData"),
        (block_a_ref, "GeometryBlockA"),
        (block_b_ref, "GeometryBlockB"),
        (byte_table_ref, "GeometryByteTable"),
    ]
    if float_runs:
        section_refs.append((float_runs[0][0], f"VertexPositions ({float_runs[0][2] // 3} vertices)"))
    toc_lines.append("[RootTables.SectionGeometry]")
    seen_section_refs: set[int] = set()
    for rel, name in section_refs:
        if rel and 0 <= rel < size and rel not in seen_section_refs:
            seen_section_refs.add(rel)
            toc_lines.append(f"@0x{rel:06X} {name}")
    toc_lines.append("")
    for table in sorted(by_table):
        toc_lines.append(f"[RootTables.{table}]")
        seen_names: set[str] = set()
        for record in by_table[table]:
            name = str(record["name"])
            if name in seen_names:
                continue
            seen_names.add(name)
            toc_lines.append(f"@0x{int(record['start']):06X} {MD.display_name(name)}")
        toc_lines.append("")
    return records, rows, toc_lines


def scan_level_string_roots(data: bytes | bytearray, strings: list[str], base: int, size: int, endian: str | None = "<") -> dict[int, str]:
    roots: dict[int, str] = {}
    rel = 0
    while rel <= size - 4:
        raw = u32e(data, base + rel, endian)
        if 0 <= raw < len(strings) and MD.is_meaningful_string(strings[raw]):
            value = strings[raw]
            stem = level_value_stem(value)
            if stem and stem not in {"Value", "None"}:
                # String-tagged records usually declare their name/type at or near the record start.
                record_start = rel
                for back in (0x0C, 0x08, 0x04):
                    probe = rel - back
                    if probe >= 0:
                        probe_raw = u32e(data, base + probe, endian)
                        if probe_raw % 4 == 0 and 0 < probe_raw < size:
                            record_start = probe
                            break
                roots.setdefault(record_start, stem)
        rel += 4
    return roots


def level_field_name(data: bytes | bytearray, strings: list[str], absolute: int, raw: int, size: int, endian: str | None = "<") -> str:
    if raw != 0 and 0 <= raw < len(strings) and MD.is_meaningful_string(strings[raw]):
        return "Name"
    if raw % 4 == 0 and 0x20 <= raw < size:
        return "Ref"
    exponent = (raw >> 23) & 0xFF
    value = f32e(data, absolute, endian)
    if raw != 0 and 0x70 <= exponent <= 0x8E and abs(value) < 1000000.0:
        return "Float"
    if MD.looks_like_u16x2(raw):
        return "Pair"
    if MD.looks_like_u8x4(raw):
        return "Bytes"
    return "Int"


def level_owned_labels(
    data: bytes | bytearray,
    strings: list[str],
    base: int,
    size: int,
    roots: dict[int, str],
    occupied: set[int],
    endian: str | None = "<",
) -> tuple[dict[int, str], dict[int, str]]:
    labels: dict[int, str] = {}
    forced_types: dict[int, str] = {}
    ordered = sorted((rel, stem) for rel, stem in roots.items() if 0 <= rel < size)
    for index, (start, stem) in enumerate(ordered):
        end = ordered[index + 1][0] if index + 1 < len(ordered) else min(size, start + 0x400)
        if end <= start or end - start > 0x4000:
            continue
        counters: dict[str, int] = {}
        for rel in range(start, min(end, size - 3), 4):
            if rel in occupied:
                continue
            raw = u32e(data, base + rel, endian)
            field = level_field_name(data, strings, base + rel, raw, size, endian)
            count = counters.get(field, 0)
            counters[field] = count + 1
            suffix = "" if count == 0 else f"{count:02d}"
            labels[rel] = f"LevelData.{stem}.{field}{suffix}"
            if field == "Name":
                forced_types[rel] = "string"
            elif field == "Ref":
                forced_types[rel] = "ref"
            elif field == "Float":
                forced_types[rel] = "f32"
            elif field == "Pair":
                forced_types[rel] = "u16x2"
            elif field == "Bytes":
                forced_types[rel] = "u8x4"
            else:
                forced_types[rel] = "int"
    return labels, forced_types


def explicit_root_toc_lines(roots: dict[int, str], pointer_runs: list[dict[str, int]]) -> list[str]:
    lines = [
        "# Click on table names to view contents",
        "[RootTables.LevelData]",
    ]
    seen: set[int] = set()
    seen_names: set[str] = set()
    for rel, stem in sorted(roots.items()):
        if rel in seen:
            continue
        display = MD.display_name(stem)
        if display in seen_names:
            continue
        seen.add(rel)
        seen_names.add(display)
        lines.append(f"@0x{rel:06X} {display}")
    for index, run in enumerate(pointer_runs):
        start = int(run["start"])
        if start in seen:
            continue
        seen.add(start)
        lines.append(f"@0x{start:06X} PointerDirectory{index:03d}")
    lines.append("")
    return lines


def export_txt(bundle_path: Path, out_path: Path, entry_name: str | None = None) -> None:
    bundle_path = bundle_path.resolve()
    data, _parser, _entries, strings, level_data = parse_bundle(bundle_path, entry_name)
    base, size = character_data_span(level_data)
    endian = str(level_data.get("endian", "<") or "<")
    records, structured_rows, toc_lines = collect_structured_level_rows(data, strings, base, size, endian)
    record_by_start = {int(record["start"]): record for record in records}

    lines: list[str] = [
        "# LevelData text export",
        f"# SourceCLP={bundle_path}",
        f"# LevelData={level_data['name']}",
        f"# LevelDataOffset=0x{base:X}",
        f"# LevelDataSize=0x{size:X}",
        f"# Endian={'big' if endian == '>' else 'little'}",
        "# Format: @offset <type> <name> = <value>",
        "# Types: string, float, int, ref, bool, u16x2, u8x4.",
        "# Layout notes: tagged LevelDB records; Wii BDG is big-endian, PS2 CLP is little-endian.",
        "# Opaque packed/code ranges are intentionally omitted until their structure is confirmed.",
        "",
    ]
    lines.extend(toc_lines)
    lines.append("[LevelData]")

    previous_record_start: int | None = None
    in_section_geometry = False
    in_wii_refs = False
    for rel, (force, label) in sorted(structured_rows.items()):
        current_record = None
        starts = [int(record["start"]) for record in records if int(record["start"]) <= rel < int(record["end"])]
        if starts:
            current_record = max(starts)
        is_section_geometry = label.startswith("SectionGeometry.")
        is_wii_ref = label.startswith("WiiLevelRefs.")
        if is_section_geometry and not in_section_geometry:
            if lines[-1] != "":
                lines.append("")
            lines.append("## SectionGeometry (stage mesh / static geometry vertex data)")
            in_section_geometry = True
            in_wii_refs = False
        elif in_section_geometry and not is_section_geometry:
            if lines[-1] != "":
                lines.append("")
            in_section_geometry = False
        if is_wii_ref and not in_wii_refs:
            if lines[-1] != "":
                lines.append("")
            lines.append("## WiiLevelRefs (confirmed Wii LevelData string references)")
            in_wii_refs = True
        elif in_wii_refs and not is_wii_ref:
            if lines[-1] != "":
                lines.append("")
            in_wii_refs = False
        if current_record is not None and current_record != previous_record_start:
            record = record_by_start.get(current_record)
            if lines[-1] != "":
                lines.append("")
            if record is not None:
                lines.append(f"## {record['table']} LevelData+0x{current_record:06X} {MD.display_name(str(record['name']))}")
            previous_record_start = current_record
        elif previous_record_start is not None and current_record is None and lines[-1] != "":
            lines.append("")
        row_type, value_text = export_row_type_and_value(data, strings, base + rel, force, endian)
        lines.append(f"@0x{rel:06X} {row_type:<12} {label} = {value_text}")

    out_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"Wrote {out_path}")
    print(f"Exported {len(structured_rows)} named LevelData values from {level_data['name']}.")
    print(f"Annotated {len(records)} LevelDB records.")
    if ENGINE_LEVEL_TERMS:
        print(f"Loaded {len(ENGINE_LEVEL_TERMS)} engine LevelDB terms.")


def metadata_from_txt(txt_path: Path) -> dict[str, str]:
    meta: dict[str, str] = {}
    for line in txt_path.read_text(encoding="utf-8").splitlines():
        match = META_RE.match(line)
        if match:
            meta[match.group(1).strip()] = match.group(2).strip()
    return meta


def rebuild_zip_for_bundle(bundle_path: Path, payload: bytes) -> bool:
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
    return replaced


def import_txt(txt_path: Path, bundle_override: Path | None = None, dry_run: bool = False) -> None:
    meta = metadata_from_txt(txt_path)
    bundle_path = bundle_override
    if bundle_path is None:
        raw_source = meta.get("SourceCLP")
        bundle_path = Path(raw_source) if raw_source else None
    if bundle_path is None or not bundle_path.exists():
        bundle_path = pick_open_file(
            "Select CLP bundle to update",
            [("CLP bundles", "*.clp *.CLP"), ("All files", "*.*")],
            STAGE_DIR,
        )
    bundle_path = (ROOT / bundle_path).resolve() if not bundle_path.is_absolute() else bundle_path.resolve()

    entry_name = meta.get("LevelData")
    data, _parser, _entries, strings, level_data = parse_bundle(bundle_path, entry_name)
    base, size = character_data_span(level_data)
    endian = str(level_data.get("endian", "<") or "<")
    text = txt_path.read_text(encoding="utf-8")
    ref_lookup = MD.build_ref_name_lookup_from_text(text)
    MD.augment_ref_lookup_with_current_refs(text, data, base, size, ref_lookup)
    changes: list[dict[str, object]] = []
    wanted: dict[int, tuple[str, bytes, str, str, int]] = {}
    conflicts: list[str] = []

    for line in text.splitlines():
        match = ROW_RE.match(line.strip())
        if not match:
            continue
        rel = int(match.group(1), 16)
        kind = match.group(2)
        label = match.group(3).strip()
        value_text = match.group(4).strip()
        ascii_size = MD.parse_ascii_kind(kind)
        if ascii_size is None and kind not in {"string", "u32", "f32", "float", "int", "word", "ref", "bool", "u16x2", "u8x4"}:
            continue
        edit_size = ascii_size or 4
        if rel < 0 or rel + edit_size > size or rel % 4:
            continue
        old_bytes = bytes(data[base + rel : base + rel + edit_size])
        if kind == "string" and edit_size == 4 and value_text == string_value(data, strings, base + rel, endian):
            continue
        try:
            new_bytes = parse_new_value(kind, value_text, strings, ref_lookup, endian)
        except ValueError:
            if kind != "string":
                raise
            value = MD.strip_inline_comment(value_text)
            prefixed = "000" + value
            if prefixed in strings:
                new_bytes = strings.index(prefixed).to_bytes(4, endian_byteorder(endian))
            else:
                raise
        if old_bytes == new_bytes:
            continue
        previous = wanted.get(rel)
        if previous and previous[1] != new_bytes:
            conflicts.append(f"@0x{rel:06X} has conflicting edits: {previous[2]} vs {value_text}")
            continue
        wanted[rel] = (kind, new_bytes, value_text, label, edit_size)

    if conflicts:
        raise RuntimeError("Conflicting duplicate-offset edits:\n  " + "\n  ".join(conflicts))

    for rel, (kind, new_bytes, value_text, label, edit_size) in sorted(wanted.items()):
        absolute = base + rel
        old_text = row_value(data, strings, absolute, kind, endian) if edit_size == 4 else MD.quote_text(MD.read_fixed_ascii(data, absolute, edit_size))
        data[absolute : absolute + edit_size] = new_bytes
        new_text = row_value(data, strings, absolute, kind, endian) if edit_size == 4 else MD.quote_text(MD.read_fixed_ascii(data, absolute, edit_size))
        changes.append(
            {
                "offset": f"LevelData+0x{rel:06X}",
                "type": kind,
                "label": label,
                "old": old_text,
                "new": new_text,
                "requested": value_text,
            }
        )

    if not changes:
        print("No changed editable LevelData values found.")
        return

    print(f"{'Would apply' if dry_run else 'Applying'} {len(changes)} LevelData changes to {bundle_path}:")
    for change in changes[:60]:
        print(f"  {change['offset']} {change['label']}: {change['old']} -> {change['new']}")
    if len(changes) > 60:
        print(f"  ... {len(changes) - 60} more")

    if dry_run:
        return

    backup_dir = BACKUP_ROOT / f"level_data_txt_import_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    clp_backup = backup_dir / bundle_path.relative_to(ROOT)
    clp_backup.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(bundle_path, clp_backup)
    zip_path = bundle_path.with_suffix(".zip")
    if zip_path.exists():
        zip_backup = backup_dir / zip_path.relative_to(ROOT)
        zip_backup.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(zip_path, zip_backup)

    bundle_path.write_bytes(data)
    zip_rebuilt = rebuild_zip_for_bundle(bundle_path, bytes(data))
    print(f"Backup: {backup_dir}")
    print(f"Rebuilt zip: {zip_rebuilt}")


def interactive_main() -> int:
    print("LevelData TXT Tool")
    print("1. Export CLP LevelData to txt")
    print("2. Import txt back into CLP LevelData")
    choice = ask("Choose mode", "1")
    if choice == "1":
        bundle_path = pick_open_file(
            "Select stage CLP bundle",
            [("CLP bundles", "*.clp *.CLP"), ("All files", "*.*")],
            STAGE_DIR,
        )
        out_path = pick_save_file(
            "Save LevelData txt",
            f"{bundle_path.stem}_LevelData.txt",
            [("Text files", "*.txt"), ("All files", "*.*")],
        )
        export_txt(bundle_path, out_path)
    elif choice == "2":
        txt_path = pick_open_file(
            "Select edited LevelData txt",
            [("Text files", "*.txt"), ("All files", "*.*")],
            ROOT,
        )
        import_txt(txt_path)
    else:
        raise ValueError("Choose 1 or 2")
    return 0


def cli_main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Export/import editable PS2 CLP LevelData rows.")
    sub = parser.add_subparsers(dest="cmd")

    export_p = sub.add_parser("export", help="Export a stage CLP's LevelData to txt.")
    export_p.add_argument("clp", type=Path)
    export_p.add_argument("--out", type=Path)
    export_p.add_argument("--entry", help="LevelData entry name substring")

    import_p = sub.add_parser("import", help="Import edited LevelData txt into its source CLP.")
    import_p.add_argument("txt", type=Path)
    import_p.add_argument("--clp", type=Path)
    import_p.add_argument("--dry-run", action="store_true")

    args = parser.parse_args(argv)
    if args.cmd == "export":
        out = args.out or args.clp.with_name(f"{args.clp.stem}_LevelData.txt")
        export_txt(args.clp, out, args.entry)
        return 0
    if args.cmd == "import":
        import_txt(args.txt, args.clp, args.dry_run)
        return 0
    return interactive_main()


if __name__ == "__main__":
    raise SystemExit(cli_main(sys.argv[1:]))
