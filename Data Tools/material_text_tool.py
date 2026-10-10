"""Editable, lossless text view for Pipeworks type-6 material records."""

from __future__ import annotations

import re
import struct


FIELD_RE = re.compile(
    r"^\s*@0x([0-9A-Fa-f]+)\s+(u16|u32|float|color|bytes)\s+"
    r"([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?);\s*$"
)


def _float_text(value: float) -> str:
    return f"{value:.9g}"


def decode_material(data: bytes, endian: str, name: str = "Material") -> str:
    if endian not in {"<", ">"}:
        raise ValueError("Material endian must be '<' or '>'")
    if len(data) < 0x38:
        raise ValueError("Material record is too small")
    endian_name = "little" if endian == "<" else "big"
    lines = [
        f'material "{name}"',
        "{",
        f"    endian = {endian_name};",
        f"    size = {len(data)};",
        "",
        f"    @0x0000 u16 HeaderId = {struct.unpack_from(endian + 'H', data, 0)[0]};",
        f"    @0x0002 u16 HeaderFlags = {struct.unpack_from(endian + 'H', data, 2)[0]};",
        f"    @0x0004 u32 RenderFlags = 0x{struct.unpack_from(endian + 'I', data, 4)[0]:08X};",
    ]
    for offset, field_name in ((0x08, "Color0"), (0x18, "Color1"), (0x28, "Color2")):
        values = struct.unpack_from(endian + "4f", data, offset)
        lines.append(
            f"    @0x{offset:04X} color {field_name} = "
            + ", ".join(_float_text(value) for value in values)
            + ";"
        )
    lines.extend((
        f"    @0x0034 float Shininess = {_float_text(struct.unpack_from(endian + 'f', data, 0x34)[0])};",
        "",
        "    state",
        "    {",
    ))
    offset = 0x38
    default_word_count = 0
    while offset + 4 <= len(data):
        value = struct.unpack_from(endian + "I", data, offset)[0]
        if value:
            field_name = "RenderStateFlags" if offset == 0x38 else f"State_{offset:04X}"
            lines.append(f"        @0x{offset:04X} u32 {field_name} = 0x{value:08X};")
        else:
            default_word_count += 1
        offset += 4
    if default_word_count:
        suffix = "word" if default_word_count == 1 else "words"
        lines.append(f"        # {default_word_count} default zero {suffix} preserved from source")
    if offset < len(data):
        tail = data[offset:].hex(" ").upper()
        lines.append(f"        @0x{offset:04X} bytes Tail = {tail};")
    lines.extend(("    }", "}", ""))
    return "\n".join(lines)


def encode_material(text: str, original: bytes, endian: str) -> bytes:
    if endian not in {"<", ">"}:
        raise ValueError("Material endian must be '<' or '>'")
    output = bytearray(original)
    edits = 0
    for line_number, line in enumerate(text.splitlines(), 1):
        match = FIELD_RE.match(line)
        if not match:
            continue
        offset = int(match.group(1), 16)
        kind = match.group(2)
        value_text = match.group(4).strip()
        try:
            if kind == "u16":
                value = int(value_text, 0)
                encoded = struct.pack(endian + "H", value)
            elif kind == "u32":
                value = int(value_text, 0)
                encoded = struct.pack(endian + "I", value & 0xFFFFFFFF)
            elif kind == "float":
                encoded = struct.pack(endian + "f", float(value_text))
            elif kind == "color":
                values = [float(part.strip()) for part in value_text.split(",")]
                if len(values) != 4:
                    raise ValueError("colors require four comma-separated values")
                encoded = struct.pack(endian + "4f", *values)
            else:
                encoded = bytes.fromhex(value_text)
        except (ValueError, struct.error) as exc:
            raise ValueError(f"Line {line_number}: {exc}") from exc
        if offset < 0 or offset + len(encoded) > len(output):
            raise ValueError(f"Line {line_number}: field exceeds the {len(output)}-byte material record")
        output[offset:offset + len(encoded)] = encoded
        edits += 1
    if not edits:
        raise ValueError("No editable material fields were found")
    return bytes(output)
