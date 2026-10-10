"""Editable text codec for Pipeworks FDF font metadata and 36-byte glyph records."""

from __future__ import annotations

import ast
import re
import struct

try:
    from PIL import Image
except Exception:
    Image = None


HEADER_RE = re.compile(r"^\s*(InternalName|AtlasFile|FontRecipe)\s*=\s*(.+?);\s*$", re.MULTILINE)
GLYPH_RE = re.compile(
    r"glyph\s+\[(\d+)\]\s+(.+?)\s+@0x([0-9A-Fa-f]+)\s*\{(.*?)^\s*\}",
    re.MULTILINE | re.DOTALL,
)
FIELD_RE = re.compile(r"^\s*(ULeft|URight|VTop|VBottom|Scale|Width|XOffset|Height|Codepoint)\s*=\s*([^;]+);", re.MULTILINE)


def layout_guess(data: bytes):
    terminator = data.find(b"\0", 0x358)
    if terminator < 0:
        terminator = 0x358
    first_possible = (terminator + 4) & ~3
    candidates = []
    for stride in (36, 52):
        for start in range(first_possible, min(len(data), first_possible + 0x24), 4):
            remaining = len(data) - start
            if remaining <= 0 or remaining % stride:
                continue
            count = remaining // stride
            if not (1 <= count <= 512):
                continue
            penalty = sum(byte != 0 for byte in data[terminator + 1:start])
            candidates.append((penalty * 8 + start - first_possible, start, stride, count))
    return min(candidates, default=(0, len(data), 0, 0))[1:]


def _fixed_ascii(data, offset, size):
    return data[offset:offset + size].split(b"\0", 1)[0].decode("latin-1", errors="replace")


def _float(value):
    return f"{value:.9g}"


def decode_fdf(data: bytes, entry_name="Font"):
    if len(data) < 0x358:
        raise ValueError("FDF record is too small")
    start, stride, count = layout_guess(data)
    characters = data[0x358:].split(b"\0", 1)[0].decode("latin-1", errors="replace")
    lines = [
        "# Pipeworks FDF font source",
        f"# Entry={entry_name}",
        "# Atlas Preview opens the referenced type-9 texture; Replace PNG updates that resource.",
        "",
        "font",
        "{",
        f"    InternalName = {_fixed_ascii(data, 0x000, 0x100)!r};",
        f"    AtlasFile = {_fixed_ascii(data, 0x100, 0x100)!r};",
        f"    FontRecipe = {_fixed_ascii(data, 0x200, 0x100)!r};",
        f"    Characters = {characters!r};  # preserved mapping string",
        f"    GlyphRecordOffset = 0x{start:04X};",
        f"    GlyphRecordSize = {stride};",
        f"    GlyphRecordCount = {count};",
        "",
        "    glyph_records",
        "    {",
    ]
    for index in range(count):
        offset = start + index * stride
        character = characters[index] if index < len(characters) else "?"
        if stride != 36:
            words = [struct.unpack_from("<I", data, pos)[0] for pos in range(offset, offset + stride, 4)]
            lines.append(f"        [{index:03d}] {character!r} @0x{offset:04X} raw = " + ", ".join(f"0x{x:08X}" for x in words) + ";")
            continue
        values = struct.unpack_from("<8fI", data, offset)
        codepoint = values[8]
        display = chr(codepoint) if 0 <= codepoint <= 0x10FFFF else character
        lines.extend((
            f"        glyph [{index:03d}] {display!r} @0x{offset:04X} {{",
            f"            ULeft = {_float(values[0])};",
            f"            URight = {_float(values[1])};",
            f"            VTop = {_float(values[2])};",
            f"            VBottom = {_float(values[3])};",
            f"            Scale = {_float(values[4])};",
            f"            Width = {_float(values[5])};",
            f"            XOffset = {_float(values[6])};",
            f"            Height = {_float(values[7])};",
            f"            Codepoint = 0x{codepoint:04X};",
            "        }",
        ))
    lines.extend(("    }", "}", ""))
    return "\n".join(lines)


def _parse_string(value, field):
    try:
        parsed = ast.literal_eval(value.strip())
    except Exception as exc:
        raise ValueError(f"{field} must be a quoted string") from exc
    if not isinstance(parsed, str):
        raise ValueError(f"{field} must be a quoted string")
    return parsed


def _put_fixed_ascii(output, offset, size, value, field):
    encoded = value.encode("latin-1")
    if len(encoded) >= size:
        raise ValueError(f"{field} is too long (maximum {size - 1} bytes)")
    output[offset:offset + size] = encoded + b"\0" * (size - len(encoded))


def encode_fdf(text: str, original: bytes):
    output = bytearray(original)
    start, stride, count = layout_guess(original)
    headers = {match.group(1): _parse_string(match.group(2), match.group(1)) for match in HEADER_RE.finditer(text)}
    for required in ("InternalName", "AtlasFile", "FontRecipe"):
        if required not in headers:
            raise ValueError(f"Missing {required}")
    _put_fixed_ascii(output, 0x000, 0x100, headers["InternalName"], "InternalName")
    _put_fixed_ascii(output, 0x100, 0x100, headers["AtlasFile"], "AtlasFile")
    _put_fixed_ascii(output, 0x200, 0x100, headers["FontRecipe"], "FontRecipe")
    if stride != 36:
        return bytes(output)

    records = {}
    for match in GLYPH_RE.finditer(text):
        index = int(match.group(1))
        offset = int(match.group(3), 16)
        fields = {field.group(1): field.group(2).strip() for field in FIELD_RE.finditer(match.group(4))}
        records[index] = (offset, fields)
    if set(records) != set(range(count)):
        missing = sorted(set(range(count)) - set(records))
        raise ValueError(f"Glyph records must remain complete; missing indexes {missing[:8]}")
    names = ("ULeft", "URight", "VTop", "VBottom", "Scale", "Width", "XOffset", "Height")
    for index in range(count):
        offset, fields = records[index]
        expected = start + index * stride
        if offset != expected:
            raise ValueError(f"Glyph [{index:03d}] offset must remain 0x{expected:04X}")
        missing = [name for name in (*names, "Codepoint") if name not in fields]
        if missing:
            raise ValueError(f"Glyph [{index:03d}] is missing {', '.join(missing)}")
        floats = [float(fields[name]) for name in names]
        codepoint = int(fields["Codepoint"], 0)
        struct.pack_into("<8fI", output, offset, *floats, codepoint)
    return bytes(output)


def render_sample(text: str, atlas_path, sample="ABCDEFGHIJKLMNOPQRSTUVWXYZ\nabcdefghijklmnopqrstuvwxyz 0123456789"):
    if Image is None:
        return None
    atlas = Image.open(atlas_path).convert("RGBA")
    glyphs = {}
    for match in GLYPH_RE.finditer(text):
        fields = {field.group(1): field.group(2).strip() for field in FIELD_RE.finditer(match.group(4))}
        required = {"ULeft", "URight", "VTop", "VBottom", "Scale", "Width", "XOffset", "Height", "Codepoint"}
        if not required.issubset(fields):
            continue
        codepoint = int(fields["Codepoint"], 0)
        glyph = {
            name: float(fields[name]) for name in required - {"Codepoint"}
        }
        if (
            not all(abs(glyph[name]) <= 2.0 for name in ("ULeft", "URight", "VTop", "VBottom"))
            or not (0 < abs(glyph["Scale"]) <= 100)
            or not (0 < abs(glyph["Width"]) <= 1024 and 0 < abs(glyph["Height"]) <= 1024)
        ):
            continue
        glyphs[chr(codepoint)] = glyph
    if not glyphs:
        return None
    lines = sample.splitlines() or [sample]
    line_height = max(16, int(max(abs(item["Height"] * item["Scale"]) for item in glyphs.values()) + 8))
    canvas = Image.new("RGBA", (900, max(70, line_height * len(lines) + 24)), (15, 23, 33, 255))
    for line_index, line in enumerate(lines):
        x = 12
        baseline = 12 + line_index * line_height
        for character in line:
            glyph = glyphs.get(character)
            if glyph is None:
                x += max(4, line_height // 3)
                continue
            left = max(0, min(atlas.width, round(glyph["ULeft"] * atlas.width)))
            right = max(left + 1, min(atlas.width, round(glyph["URight"] * atlas.width)))
            top = max(0, min(atlas.height, round(glyph["VTop"] * atlas.height)))
            bottom = max(top + 1, min(atlas.height, round(glyph["VBottom"] * atlas.height)))
            image = atlas.crop((left, top, right, bottom))
            target_w = max(1, round(abs(glyph["Width"] * glyph["Scale"])))
            target_h = max(1, round(abs(glyph["Height"] * glyph["Scale"])))
            if image.size != (target_w, target_h):
                resampling = getattr(Image, "Resampling", Image)
                image = image.resize((target_w, target_h), getattr(resampling, "LANCZOS", Image.LANCZOS))
            canvas.alpha_composite(image, (max(0, round(x + glyph["XOffset"])), baseline))
            x += max(1, target_w)
            if x >= canvas.width - 20:
                break
    bbox = canvas.getbbox()
    return canvas.crop((0, 0, min(canvas.width, max(320, bbox[2] + 12)), canvas.height)) if bbox else canvas
