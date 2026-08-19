from __future__ import annotations

import argparse
import shutil
import struct
import sys
import textwrap
from dataclasses import dataclass
from collections import OrderedDict
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
COMMON_BDG = ROOT / "DATA" / "files" / "Game" / "common.bdg"

TYPE_FLOAT = 0x01160000
TYPE_FLOAT_ALT = 0x00160000
TYPE_INT = 0x01140000
TYPE_INT_ALT = 0x00140000
TYPE_STRING = 0x02160000
TYPE_REF_A = 0x03160000
TYPE_REF_B = 0x03170006

EDITABLE_TYPES = {
    TYPE_FLOAT,
    TYPE_FLOAT_ALT,
    TYPE_INT,
    TYPE_INT_ALT,
    TYPE_STRING,
}

KNOWN_PRX = {
    "monsterai": "22/MonsterAI.prx",
    "monster": "22/MonsterAI.prx",
    "buildingdamage": "22/BuildingDamage.prx",
    "building": "22/BuildingDamage.prx",
    "beamfight": "22/BeamFight.prx",
    "beam": "22/BeamFight.prx",
}


@dataclass
class Row:
    prx_name: str
    group: str
    table_offset: int
    row_offset: int
    type_id: int
    value_raw: int
    name_id: int
    name: str
    index: int

    @property
    def key(self) -> str:
        suffix = "" if self.index == 1 else f"#{self.index}"
        return f"{self.group}.{self.name}{suffix}"

    @property
    def type_name(self) -> str:
        if self.type_id == TYPE_FLOAT:
            return "float"
        if self.type_id in (TYPE_INT, TYPE_INT_ALT, TYPE_FLOAT_ALT):
            return "int"
        if self.type_id == TYPE_STRING:
            return "string"
        if self.type_id in (TYPE_REF_A, TYPE_REF_B):
            return "ref"
        return f"0x{self.type_id:08X}"

    def value(self, strings: list[str]) -> int | float | str:
        if self.type_id == TYPE_FLOAT:
            return struct.unpack(">f", struct.pack(">I", self.value_raw))[0]
        if self.type_id in (TYPE_INT, TYPE_INT_ALT, TYPE_FLOAT_ALT):
            return signed32(self.value_raw)
        if self.type_id == TYPE_STRING:
            if 0 <= self.value_raw < len(strings):
                return strings[self.value_raw]
            return f"string_{self.value_raw}"
        return signed32(self.value_raw)


def u32(data: bytes | bytearray, off: int) -> int:
    return struct.unpack_from(">I", data, off)[0]


def put_u32(data: bytearray, off: int, value: int) -> None:
    struct.pack_into(">I", data, off, value & 0xFFFFFFFF)


def signed32(value: int) -> int:
    return value - 0x100000000 if value & 0x80000000 else value


def resolve_prx_name(name: str) -> str:
    if name in KNOWN_PRX.values():
        return name
    key = name.lower().replace("_", "").replace("-", "")
    if key in KNOWN_PRX:
        return KNOWN_PRX[key]
    if not name.endswith(".prx"):
        name = f"{name}.prx"
    if not name.startswith("22/"):
        name = f"22/{name}"
    return name


def read_strings(data: bytes, string_offset: int) -> list[str]:
    count = struct.unpack_from("<I", data, string_offset)[0]
    strings: list[str] = []
    for i in range(count):
        rel = struct.unpack_from("<I", data, string_offset + 4 + i * 4)[0]
        pos = string_offset + rel
        end = data.index(b"\0", pos)
        strings.append(data[pos:end].decode("ascii", errors="replace"))
    return strings


def read_bundle(prx_name: str) -> tuple[bytearray, dict, list[str]]:
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import light_bdg  # type: ignore

    data = bytearray(COMMON_BDG.read_bytes())
    parser = light_bdg.PipeworksParser("common.bdg")
    entries = parser.parse_from_data(bytes(data))
    resolved = resolve_prx_name(prx_name)
    prx = next((e for e in entries if e["name"] == resolved), None)
    if prx is None:
        available = ", ".join(e["name"] for e in entries if str(e["name"]).endswith(".prx"))
        raise SystemExit(f"Could not find {resolved}. PRX files: {available}")
    strings = read_strings(bytes(data), parser.string_offset)
    return data, prx, strings


def table_count_at(prx: bytes | bytearray, table_offset: int) -> int | None:
    if not (0 <= table_offset <= len(prx) - 8):
        return None
    if u32(prx, table_offset) != 1:
        return None
    count_word = u32(prx, table_offset + 4)
    count_a = count_word >> 16
    count_b = count_word & 0xFFFF
    if count_a != count_b or not (1 <= count_a <= 256):
        return None
    ptr_end = table_offset + 8 + count_a * 4
    if ptr_end > len(prx):
        return None
    for i in range(count_a):
        rel = signed32(u32(prx, table_offset + 8 + i * 4))
        row_off = table_offset + rel - 4
        if not (0 <= row_off <= len(prx) - 12):
            return None
    return count_a


def find_root_tables(prx: bytes | bytearray, strings: list[str]) -> dict[str, int]:
    roots: dict[str, int] = {}
    first_table = len(prx)
    for off in range(0, len(prx) - 8, 4):
        if table_count_at(prx, off) is not None:
            first_table = off
            break

    scan_end = max(first_table, min(len(prx), 0x600))
    for row_off in range(0, scan_end - 12, 4):
        if u32(prx, row_off) not in (TYPE_REF_A, TYPE_REF_B):
            continue
        name_id = u32(prx, row_off + 8)
        if not (0 <= name_id < len(strings)):
            continue
        target = row_off + signed32(u32(prx, row_off + 4))
        if table_count_at(prx, target) is None and table_count_at(prx, target + 4) is not None:
            target += 4
        if table_count_at(prx, target) is None:
            continue
        roots[strings[name_id]] = target
    return roots


def parse_table(
    prx_name: str,
    prx: bytes | bytearray,
    strings: list[str],
    group: str,
    table_offset: int,
) -> list[Row]:
    count = table_count_at(prx, table_offset)
    if count is None:
        return []
    rows: list[Row] = []
    name_counts: dict[str, int] = {}
    seen: set[int] = set()
    for i in range(count):
        rel = signed32(u32(prx, table_offset + 8 + i * 4))
        row_off = table_offset + rel - 4
        if row_off in seen:
            continue
        seen.add(row_off)
        type_id = u32(prx, row_off)
        value_raw = u32(prx, row_off + 4)
        name_id = u32(prx, row_off + 8)
        if not (0 <= name_id < len(strings)):
            continue
        if type_id not in EDITABLE_TYPES and type_id not in (TYPE_REF_A, TYPE_REF_B):
            continue
        name = strings[name_id]
        name_counts[name] = name_counts.get(name, 0) + 1
        rows.append(Row(prx_name, group, table_offset, row_off, type_id, value_raw, name_id, name, name_counts[name]))
    return rows


def parse_rows(common: bytes | bytearray, prx_entry: dict, strings: list[str]) -> tuple[bytearray, list[Row], dict[str, int]]:
    prx = bytearray(common[prx_entry["offset"] : prx_entry["offset"] + prx_entry["size"]])
    roots = find_root_tables(prx, strings)
    rows: list[Row] = []

    def add_table(group: str, table_offset: int, seen_tables: set[int]) -> None:
        if table_offset in seen_tables:
            return
        seen_tables.add(table_offset)
        table_rows = parse_table(prx_entry["name"], prx, strings, group, table_offset)
        rows.extend(table_rows)
        for row in table_rows:
            if row.type_id not in (TYPE_REF_A, TYPE_REF_B):
                continue
            target = row.row_offset + signed32(row.value_raw)
            if table_count_at(prx, target) is None and table_count_at(prx, target + 4) is not None:
                target += 4
            if table_count_at(prx, target) is not None:
                add_table(f"{group}.{row.name}", target, seen_tables)

    for group, table_offset in sorted(roots.items(), key=lambda item: item[1]):
        add_table(group, table_offset, set())
    return prx, rows, roots


def row_value_text(row: Row, strings: list[str]) -> str:
    value = row.value(strings)
    if isinstance(value, float):
        return repr(float(value))
    return str(value)


def display_rows_by_offset(rows: list[Row]) -> list[Row]:
    unique: dict[tuple[int, str, str], Row] = {}
    for row in rows:
        unique.setdefault((row.row_offset, row.type_name, row.key), row)
    return sorted(unique.values(), key=lambda item: (prx_display_group_name(item), item.table_offset, item.row_offset, item.name.lower()))


def prx_display_group_name(row: Row) -> str:
    return row.group.split(".", 1)[0]


def prx_table_groups(rows: list[Row]) -> "OrderedDict[str, int]":
    tables: "OrderedDict[str, int]" = OrderedDict()
    for row in display_rows_by_offset(rows):
        group = prx_display_group_name(row)
        if group not in tables or row.table_offset < tables[group]:
            tables[group] = row.table_offset
    return tables


def prx_root_toc_lines(roots: dict[str, int], rows: list[Row]) -> list[str]:
    lines: list[str] = [
        "# Click on table names to view contents",
        "[RootTables.PRXRoots]",
    ]
    seen_root_offsets: set[int] = set()
    for name, off in sorted(roots.items(), key=lambda item: item[1]):
        if off in seen_root_offsets:
            continue
        seen_root_offsets.add(off)
        lines.append(f"@0x{off:04X} {name}")
    lines.append("")
    tables = prx_table_groups(rows)
    if tables:
        lines.append("[RootTables.PRXTables]")
        for group, table_offset in tables.items():
            lines.append(f"@0x{table_offset:04X} {group}")
        lines.append("")
    return lines


def prx_rows_text_lines(rows: list[Row], strings: list[str]) -> list[str]:
    lines: list[str] = ["[Rows]"]
    current_group: str | None = None
    for row in display_rows_by_offset(rows):
        group = prx_display_group_name(row)
        if group != current_group:
            lines.append("")
            lines.append(f"## PRXTable 0x{row.table_offset:04X} {group}")
            current_group = group
        lines.append(f"@0x{row.row_offset:04X} {row.type_name:<10} {row.key} = {row_value_text(row, strings)}")
    return lines


def find_row(rows: list[Row], key: str) -> Row:
    key_l = key.lower()
    matches = [row for row in rows if row.key.lower() == key_l]
    if not matches and "." in key:
        group, field = key.split(".", 1)
        matches = [
            row
            for row in rows
            if row.group.lower() == group.lower()
            and (row.name.lower() == field.lower() or row.key.lower() == key_l)
        ]
    if not matches:
        raise SystemExit(f"Unknown PRX value: {key}")
    if len(matches) > 1:
        opts = ", ".join(row.key for row in matches)
        raise SystemExit(f"Ambiguous PRX value: {key}. Use one of: {opts}")
    return matches[0]


def parse_new_value(row: Row, value: str, strings: list[str]) -> int:
    if row.type_id == TYPE_FLOAT:
        return struct.unpack(">I", struct.pack(">f", float(value)))[0]
    if row.type_id in (TYPE_INT, TYPE_INT_ALT, TYPE_FLOAT_ALT):
        return int(value, 0)
    if row.type_id == TYPE_STRING:
        if value in strings:
            return strings.index(value)
        return int(value, 0)
    return int(value, 0)


def format_rows(rows: list[Row], strings: list[str]) -> str:
    out: list[str] = []
    current_group: str | None = None
    for row in display_rows_by_offset(rows):
        group = prx_display_group_name(row)
        if group != current_group:
            if out:
                out.append("")
            out.append(f"[PRXTable 0x{row.table_offset:04X} {group}]")
            current_group = group
        out.append(f"{row.key:<48} {row_value_text(row, strings):<18} {row.type_name:<6} @ prx+0x{row.row_offset + 4:04X}")
    return "\n".join(out) + "\n"


def write_common_with_prx(common: bytearray, prx_entry: dict, prx: bytearray) -> None:
    if len(prx) != prx_entry["size"]:
        raise SystemExit("Refusing to write PRX with changed size")
    backup = COMMON_BDG.with_suffix(COMMON_BDG.suffix + ".prx_value_editor.bak")
    if not backup.exists():
        shutil.copy2(COMMON_BDG, backup)
    start = prx_entry["offset"]
    common[start : start + prx_entry["size"]] = prx
    COMMON_BDG.write_bytes(common)


def cmd_dump(args: argparse.Namespace) -> None:
    common, prx_entry, strings = read_bundle(args.prx)
    _, rows, roots = parse_rows(common, prx_entry, strings)
    text = format_rows(rows, strings)
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
    print(text, end="")
    print("Groups:", ", ".join(sorted(roots)))


def cmd_get(args: argparse.Namespace) -> None:
    common, prx_entry, strings = read_bundle(args.prx)
    _, rows, _ = parse_rows(common, prx_entry, strings)
    row = find_row(rows, args.key)
    print(f"{row.key} = {row.value(strings)} ({row.type_name}, common.bdg+0x{prx_entry['offset'] + row.row_offset + 4:X})")


def cmd_set(args: argparse.Namespace) -> None:
    common, prx_entry, strings = read_bundle(args.prx)
    prx, rows, _ = parse_rows(common, prx_entry, strings)
    row = find_row(rows, args.key)
    old_value = row.value(strings)
    put_u32(prx, row.row_offset + 4, parse_new_value(row, args.value, strings))
    write_common_with_prx(common, prx_entry, prx)
    print(f"{row.key}: {old_value} -> {args.value}")
    print(f"Backup: {COMMON_BDG.with_suffix(COMMON_BDG.suffix + '.prx_value_editor.bak')}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Dump or edit common.bdg PRX property values.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(
            """\
            Examples:
              python prx_value_editor.py dump MonsterAI --out common_monster_ai_decomp.txt
              python prx_value_editor.py get BeamFight BeamFightObject.Acceleration
              python prx_value_editor.py set BuildingDamage All.BuildingRegenerationProb 0.5
            """
        ),
    )
    sub = parser.add_subparsers(dest="command", required=True)

    dump = sub.add_parser("dump")
    dump.add_argument("prx", help="MonsterAI, BuildingDamage, BeamFight, or a full PRX name.")
    dump.add_argument("--out", help="Optional text file to write the named dump to.")
    dump.set_defaults(func=cmd_dump)

    get = sub.add_parser("get")
    get.add_argument("prx")
    get.add_argument("key")
    get.set_defaults(func=cmd_get)

    set_cmd = sub.add_parser("set")
    set_cmd.add_argument("prx")
    set_cmd.add_argument("key")
    set_cmd.add_argument("value")
    set_cmd.set_defaults(func=cmd_set)

    args = parser.parse_args()
    args.func(args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
