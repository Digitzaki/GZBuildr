"""Decode and rebuild Pipeworks Type-23 LOC localization tables."""
from __future__ import annotations

import argparse
import json
import re
import struct
from dataclasses import dataclass
from pathlib import Path


HEADER_SIZE = 0x28
KEY_LINE_RE = re.compile(r'^\[(\d+)\]\s+Key\s*=\s*(.+)$')
TEXT_LINE_RE = re.compile(r'^(?:Text|[A-Za-z][A-Za-z0-9_]*)\[(\d+)\]\s*=\s*(.+)$')

# OSGetLanguageId() in Godzilla3.elf proves these BLangIds by mapping the Wii
# system-language enum to the game's localization-table index. IDs 2 and 9
# are not named by that executable, so keep neutral labels for them.
LANGUAGE_LABELS = {
    1: "EnglishUS",
    2: "EnglishUK",
    3: "Japanese",
    4: "French",
    5: "German",
    6: "Italian",
    7: "Spanish",
    8: "Dutch",
    9: "Portuguese",
}


def _language_label(index: int) -> str:
    return LANGUAGE_LABELS.get(index, "Language")


@dataclass
class LocFile:
    version: int
    language_count: int
    row_count: int
    table_starts: list[int]
    rows: list[list[str]]
    pointers: list[list[int]]
    padding: list[bytes]
    pool_start: int


def _u32(data: bytes, offset: int) -> int:
    if offset < 0 or offset + 4 > len(data):
        raise ValueError(f"LOC u32 offset 0x{offset:X} is outside the file")
    return struct.unpack_from(">I", data, offset)[0]


def _read_string(data: bytes, offset: int) -> tuple[str, int]:
    if offset <= 0 or offset >= len(data):
        raise ValueError(f"LOC string offset 0x{offset:X} is outside the file")
    end = data.find(b"\0", offset)
    if end < 0:
        raise ValueError(f"LOC string at 0x{offset:X} is not null terminated")
    try:
        value = data[offset:end].decode("cp1252")
    except UnicodeDecodeError as exc:
        raise ValueError(f"LOC string at 0x{offset:X} is not Windows-1252 text") from exc
    return value, end + 1


def parse_loc(data: bytes) -> LocFile:
    if len(data) < HEADER_SIZE:
        raise ValueError("LOC file is too small")
    version = _u32(data, 0x1C)
    language_count = _u32(data, 0x20)
    row_count = _u32(data, 0x24)
    if version != 4:
        raise ValueError(f"Unsupported LOC version {version}; expected version 4")
    if not (1 <= language_count <= 64):
        raise ValueError(f"Invalid LOC language count {language_count}")
    if not (1 <= row_count <= 1_000_000):
        raise ValueError(f"Invalid LOC row count {row_count}")

    table_count = language_count + 2
    table_header_end = HEADER_SIZE + table_count * 4
    if table_header_end > len(data):
        raise ValueError("LOC table directory extends past the file")
    table_starts = [_u32(data, HEADER_SIZE + index * 4) for index in range(table_count)]
    expected = table_header_end
    table_size = row_count * 4
    for index, table_start in enumerate(table_starts):
        if table_start != expected:
            raise ValueError(
                f"Unsupported LOC table layout at table {index}: "
                f"expected 0x{expected:X}, found 0x{table_start:X}"
            )
        expected += table_size
    if expected > len(data):
        raise ValueError("LOC pointer tables extend past the file")

    pointers = [
        [_u32(data, table_start + row * 4) for row in range(row_count)]
        for table_start in table_starts
    ]
    auxiliary = pointers[-1]
    if any(auxiliary):
        raise ValueError("This LOC uses an unsupported non-empty auxiliary pointer table")

    populated = [pointer for table in pointers[:-1] for pointer in table]
    if any(pointer == 0 for pointer in populated):
        raise ValueError("LOC key/text tables contain null string pointers")
    if populated != sorted(populated) or len(populated) != len(set(populated)):
        raise ValueError("LOC strings are not stored in supported table order")
    pool_start = populated[0]
    if pool_start < expected:
        raise ValueError("LOC string pool overlaps its pointer tables")

    strings: list[str] = []
    string_ends: list[int] = []
    for pointer in populated:
        value, end = _read_string(data, pointer)
        strings.append(value)
        string_ends.append(end)

    padding = []
    for index, end in enumerate(string_ends):
        next_offset = populated[index + 1] if index + 1 < len(populated) else len(data)
        if end > next_offset:
            raise ValueError("LOC strings overlap")
        gap = data[end:next_offset]
        # Retail files can contain orphan bytes between referenced strings.
        # Preserve every gap verbatim so an unchanged decode/rebuild is exact.
        padding.append(gap)

    populated_table_count = language_count + 1
    rows = [
        [strings[table * row_count + row] for table in range(populated_table_count)]
        for row in range(row_count)
    ]
    return LocFile(
        version=version,
        language_count=language_count,
        row_count=row_count,
        table_starts=table_starts,
        rows=rows,
        pointers=pointers,
        padding=padding,
        pool_start=pool_start,
    )


def loc_to_editable(data: bytes) -> str:
    loc = parse_loc(data)
    lines = [
        "# Pipeworks LOC localization table",
        f"# Version: {loc.version}",
        f"# Text columns: {loc.language_count}",
        f"# Rows: {loc.row_count}",
        "# Languages [02] and [09] are unsupported by Godzilla: Unleashed.",
        "# Edit quoted language values only. Keys and row counts are used by the game.",
        f"# Language indices 01 through {loc.language_count:02d} retain the file's original order.",
        "",
    ]
    for row_index, row in enumerate(loc.rows):
        lines.append(f"[{row_index:03d}] Key = {json.dumps(row[0], ensure_ascii=False)}")
        for language_index, value in enumerate(row[1:], 1):
            lines.append(
                f"{_language_label(language_index)}[{language_index:02d}] = "
                f"{json.dumps(value, ensure_ascii=False)}"
            )
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def _parse_editable(text: str, expected_rows: int, language_count: int) -> list[list[str]]:
    rows: dict[int, dict[int, str]] = {}
    current_row: int | None = None
    for line_number, raw_line in enumerate(text.splitlines(), 1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        key_match = KEY_LINE_RE.match(line)
        if key_match:
            row_index = int(key_match.group(1))
            if row_index in rows:
                raise ValueError(f"Line {line_number}: duplicate row [{row_index:03d}]")
            try:
                key = json.loads(key_match.group(2))
            except json.JSONDecodeError as exc:
                raise ValueError(f"Line {line_number}: invalid quoted key: {exc.msg}") from exc
            if not isinstance(key, str):
                raise ValueError(f"Line {line_number}: key must be quoted text")
            rows[row_index] = {0: key}
            current_row = row_index
            continue
        text_match = TEXT_LINE_RE.match(line)
        if text_match:
            if current_row is None:
                raise ValueError(f"Line {line_number}: Text value appears before a row header")
            language_index = int(text_match.group(1))
            if not (1 <= language_index <= language_count):
                raise ValueError(
                    f"Line {line_number}: Text index must be 01 through {language_count:02d}"
                )
            if language_index in rows[current_row]:
                raise ValueError(
                    f"Line {line_number}: duplicate Text[{language_index:02d}] in row {current_row:03d}"
                )
            try:
                value = json.loads(text_match.group(2))
            except json.JSONDecodeError as exc:
                raise ValueError(f"Line {line_number}: invalid quoted text: {exc.msg}") from exc
            if not isinstance(value, str):
                raise ValueError(f"Line {line_number}: value must be quoted text")
            rows[current_row][language_index] = value
            continue
        raise ValueError(f"Line {line_number}: unrecognized LOC syntax")

    expected_indexes = set(range(expected_rows))
    if set(rows) != expected_indexes:
        missing = sorted(expected_indexes - set(rows))
        extra = sorted(set(rows) - expected_indexes)
        details = []
        if missing:
            details.append("missing " + ", ".join(f"[{index:03d}]" for index in missing[:12]))
        if extra:
            details.append("unexpected " + ", ".join(f"[{index:03d}]" for index in extra[:12]))
        raise ValueError("LOC rows do not match the original file: " + "; ".join(details))

    result = []
    expected_columns = set(range(language_count + 1))
    for row_index in range(expected_rows):
        columns = rows[row_index]
        if set(columns) != expected_columns:
            missing = sorted(expected_columns - set(columns))
            raise ValueError(
                f"Row [{row_index:03d}] is missing "
                + ", ".join("Key" if index == 0 else f"Text[{index:02d}]" for index in missing)
            )
        result.append([columns[index] for index in range(language_count + 1)])
    return result


def editable_to_loc(text: str, original: bytes) -> bytes:
    loc = parse_loc(original)
    rows = _parse_editable(text, loc.row_count, loc.language_count)
    for row_index, row in enumerate(rows):
        if row[0] != loc.rows[row_index][0]:
            raise ValueError(
                f"Row [{row_index:03d}] key cannot be changed "
                f"({loc.rows[row_index][0]!r} -> {row[0]!r})"
            )
    table_values = [
        [rows[row][table] for row in range(loc.row_count)]
        for table in range(loc.language_count + 1)
    ]
    values = [value for table in table_values for value in table]
    if len(values) != len(loc.padding):
        raise ValueError("LOC editable value count does not match the original string pool")

    output = bytearray(original[:loc.pool_start])
    pointer_index = 0
    for table_index, table in enumerate(table_values):
        table_start = loc.table_starts[table_index]
        for row_index, value in enumerate(table):
            try:
                encoded = value.encode("cp1252")
            except UnicodeEncodeError as exc:
                raise ValueError(
                    f"Row [{row_index:03d}] table {table_index} contains text outside Windows-1252"
                ) from exc
            struct.pack_into(">I", output, table_start + row_index * 4, len(output))
            output.extend(encoded)
            output.append(0)
            output.extend(loc.padding[pointer_index])
            pointer_index += 1
    return bytes(output)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    decode_parser = subparsers.add_parser("decode", help="Convert LOC to editable text")
    decode_parser.add_argument("input", type=Path)
    decode_parser.add_argument("output", type=Path)
    encode_parser = subparsers.add_parser("encode", help="Rebuild LOC from editable text")
    encode_parser.add_argument("input", type=Path, help="Editable UTF-8 text")
    encode_parser.add_argument("original", type=Path, help="Original LOC template")
    encode_parser.add_argument("output", type=Path)
    args = parser.parse_args()
    if args.command == "decode":
        args.output.write_text(loc_to_editable(args.input.read_bytes()), encoding="utf-8", newline="\n")
    else:
        args.output.write_bytes(editable_to_loc(args.input.read_text(encoding="utf-8"), args.original.read_bytes()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
