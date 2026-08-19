#!/usr/bin/env python3
"""
Convert GZBuildr-dumped particle/EDF files to editable text and back.

Usage:
  python edf_dump_codec.py to-text particle_dump
  python edf_dump_codec.py to-bin particle_dump.edit.txt

The editable text keeps the original short EDF opcode in brackets, so the file
can be rebuilt even when the friendly label changes:

  graph.gen_rate [DT] = constant [KA] ? 250

Unknown or structural lines are preserved as raw escaped text:

  @raw ?{
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent
FIELD_MAP_PATH = SCRIPT_DIR / "edf_field_names.json"

DEFAULT_FIELD_NAMES = {
    "AD": "int.emitter_count",
    "AE": "enum.fxPriority",
    "DQ": "particle_entry_or_resource_id",
    "LY": "flags.emitter",
    "LZ": "flags.emitter.normalized",
    "MA": "flags.particle",
    "MB": "flags.particle.normalized",
    "DT": "graph.gen_rate",
    "DU": "graph.start_area.x",
    "DV": "graph.start_area.y",
    "DW": "graph.start_area.z",
    "DX": "graph.vel_from_start",
    "DY": "graph.em_vel.x",
    "DZ": "graph.em_vel.y",
    "EA": "graph.em_vel.z",
    "EB": "graph.em_vel_r.x",
    "EC": "graph.em_vel_r.y",
    "ED": "graph.em_vel_r.z",
    "EE": "graph.em_pt_offset.x",
    "EF": "graph.em_pt_offset.y",
    "EG": "graph.em_pt_offset.z",
    "EH": "graph.p_lifetime.min",
    "EI": "graph.p_lifetime.max",
    "EJ": "graph.p_size.min",
    "EK": "graph.p_size.max",
    "EO": "vector.em_pt_offset",
    "EP": "graph.p_vel_mult",
    "EQ": "range.cycle_length",
    "EU": "val.grav_multiplier",
    "EV": "val.air_resistance",
    "EW": "textures.name",
    "LW": "rgb.vertex_color.day",
    "LX": "rgb.vertex_color.night",
    "LO": "graph.vertex_color.r",
    "LP": "graph.vertex_color.g",
    "LQ": "graph.vertex_color.b",
    "LR": "graph.vertex_color.a",
    "EZ": "graph.blend",
    "FA": "enum.obj_col_resp",
    "FB": "enum.gnd_col_resp",
    "FC": "enum.con_col_resp",
    "FD": "enum.sound_loop_2d",
    "FH": "int.emitter_to_spawn",
    "FR": "enum.particle_mode",
    "FQ": "int.start_tile_step",
    "KJ": "int.num_tiles_or_priority",
    "MG": "particle_mode_extra",
    "KA": "constant",
    "KE": "keyframed",
    "KC": "curve",
    "LI": "default",
    "JH": "default_collision_response",
    "MK": "default_mode",
    "MP": "fx_priority",
    "AL": "priority_default",
}

SHORT_LINE_RE = re.compile(r"^\s*([A-Z][A-Z])\s*=\s*([A-Z][A-Z])?(\?)?(.*)$")
EDIT_LINE_RE = re.compile(r"^(.+?)\s+\[([A-Z][A-Z])\]\s*=\s*(?:(.+?)\s+\[([A-Z][A-Z])\]\s*)?(\?)?\s*(.*)$")
RAW_PREFIX = "@raw "
FIELD_WIDTH = 24
KIND_WIDTH = 12
VALUE_GAP = 16
UNTYPED_VALUE_GAP = 5
SHORT_VALUE_AT = 20


def load_field_names() -> dict[str, str]:
    if FIELD_MAP_PATH.exists():
        loaded = json.loads(FIELD_MAP_PATH.read_text(encoding="utf-8"))
        merged = dict(DEFAULT_FIELD_NAMES)
        merged.update({str(k): str(v) for k, v in loaded.items()})
        return merged
    return dict(DEFAULT_FIELD_NAMES)


def escape_latin1(text: str) -> str:
    out: list[str] = []
    for char in text:
        code = ord(char)
        if char == "\\":
            out.append("\\\\")
        elif char == "\t":
            out.append("\\t")
        elif 32 <= code <= 126:
            out.append(char)
        else:
            out.append(f"\\x{code:02x}")
    return "".join(out)


def unescape_latin1(text: str) -> str:
    out: list[str] = []
    index = 0
    while index < len(text):
        char = text[index]
        if char != "\\":
            out.append(char)
            index += 1
            continue
        if index + 1 >= len(text):
            out.append("\\")
            index += 1
            continue
        marker = text[index + 1]
        if marker == "\\":
            out.append("\\")
            index += 2
        elif marker == "t":
            out.append("\t")
            index += 2
        elif marker == "x" and index + 3 < len(text):
            out.append(chr(int(text[index + 2 : index + 4], 16)))
            index += 4
        else:
            out.append(marker)
            index += 2
    return "".join(out)


def field_group(friendly_key: str) -> str:
    if friendly_key.startswith("flags."):
        return "flags"
    if friendly_key.startswith("graph.vertex_color.") or friendly_key == "graph.blend":
        return "graph.render"
    if friendly_key.startswith("graph."):
        return "graph.motion"
    if friendly_key.startswith("val."):
        return "values"
    if friendly_key.startswith("textures.") or friendly_key.startswith("texture."):
        return "textures"
    if friendly_key.startswith("rgb."):
        return "rgb"
    if friendly_key.startswith("enum."):
        return "enum"
    if friendly_key.startswith("int."):
        return "int"
    return "other"


def append_blank(lines: list[str]) -> None:
    if lines and lines[-1] != "":
        lines.append("")


def dump_to_editable(data: bytes, names: dict[str, str]) -> str:
    text = data.decode("latin-1")
    lines = [
        "; EDF_DUMP_CODEC v1",
        "; Edit the values in the far-right column. Keep bracketed short codes unless you know what you are doing.",
        "",
    ]
    in_block = False
    current_group = ""
    for raw in text.splitlines():
        match = SHORT_LINE_RE.match(raw)
        if not match:
            if raw == "?{":
                append_blank(lines)
                lines.append("; ---- emitter / particle block ----")
                lines.append(RAW_PREFIX + escape_latin1(raw))
                lines.append("")
                in_block = True
                current_group = ""
                continue
            elif raw == "?}":
                append_blank(lines)
                lines.append("; ---- end block ----")
                lines.append(RAW_PREFIX + escape_latin1(raw))
                in_block = False
                current_group = ""
                continue
            lines.append(RAW_PREFIX + escape_latin1(raw))
            continue
        key, value_kind, question, value = match.groups()
        friendly_key = names.get(key, key)
        group = field_group(friendly_key)
        if in_block and current_group and group != current_group:
            append_blank(lines)
        if in_block:
            current_group = group
        key_label = f"{friendly_key:<{FIELD_WIDTH}} [{key}]"
        if value_kind:
            friendly_kind = names.get(value_kind, value_kind)
            kind_label = f"{friendly_kind:<{KIND_WIDTH}} [{value_kind}]{'?' if question else ''}"
            escaped_value = escape_latin1(value.strip())
            gap = UNTYPED_VALUE_GAP if len(escaped_value) >= SHORT_VALUE_AT else VALUE_GAP
            lines.append(f"{key_label} = {kind_label:<{KIND_WIDTH + 6}}{' ' * gap}{escaped_value}")
        elif question:
            lines.append(f"{key_label} = ?{' ' * UNTYPED_VALUE_GAP}{escape_latin1(value.strip())}")
        else:
            lines.append(f"{key_label} = {'':<{KIND_WIDTH + 6}}{' ' * VALUE_GAP}{escape_latin1(value.strip())}")
    return "\n".join(lines) + "\n"


def editable_to_dump(text: str) -> bytes:
    raw_lines: list[str] = []
    for line in text.splitlines():
        if not line or line.startswith(";"):
            continue
        if line.startswith(RAW_PREFIX):
            raw_lines.append(unescape_latin1(line[len(RAW_PREFIX) :]))
            continue
        match = EDIT_LINE_RE.match(line)
        if not match:
            raw_lines.append(unescape_latin1(line))
            continue
        _friendly_key, key, _friendly_kind, value_kind, question, value = match.groups()
        value = unescape_latin1(value.strip())
        if value_kind:
            marker = "?" if question else ""
            raw_lines.append(f"{key}={value_kind}{marker}{value}")
        elif question:
            raw_lines.append(f"{key}=?{value}")
        else:
            raw_lines.append(f"{key}={value}")
    return ("\n".join(raw_lines) + "\n").encode("latin-1")


def default_text_path(path: Path) -> Path:
    if path.suffix:
        return path.with_suffix(path.suffix + ".edit.txt")
    return path.with_name(path.name + ".edit.txt")


def default_bin_path(path: Path) -> Path:
    name = path.name
    for suffix in (".edit.txt", ".txt"):
        if name.endswith(suffix):
            return path.with_name(name[: -len(suffix)])
    return path.with_suffix(".bin")


def main() -> int:
    parser = argparse.ArgumentParser(description="Convert dumped EDF particle files to editable text and back.")
    sub = parser.add_subparsers(dest="command", required=True)

    to_text = sub.add_parser("to-text", help="Convert a GZBuildr dumped particle file to friendly editable text")
    to_text.add_argument("input", type=Path)
    to_text.add_argument("output", type=Path, nargs="?")

    to_bin = sub.add_parser("to-bin", help="Convert friendly editable text back to GZBuildr dump syntax")
    to_bin.add_argument("input", type=Path)
    to_bin.add_argument("output", type=Path, nargs="?")

    args = parser.parse_args()

    if args.command == "to-text":
        output = args.output or default_text_path(args.input)
        output.write_text(dump_to_editable(args.input.read_bytes(), load_field_names()), encoding="utf-8")
        print(f"Wrote editable text: {output}")
        return 0

    output = args.output or default_bin_path(args.input)
    output.write_bytes(editable_to_dump(args.input.read_text(encoding="utf-8")))
    print(f"Wrote rebuilt dump: {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
