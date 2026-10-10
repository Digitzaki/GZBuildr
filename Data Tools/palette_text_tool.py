import re


COLOR_RE = re.compile(r"^\s*\[(\d+)\]\s*=\s*#([0-9A-Fa-f]{8})\s*;\s*(?:#.*)?$")


def _decode_colors(data):
    if len(data) >= 1024:
        color_count = 256
        raw = data[:1024]
        stored = [tuple(raw[index:index + 4]) for index in range(0, 1024, 4)]
        colors = []
        for base in range(0, 256, 32):
            colors.extend(
                stored[base:base + 8]
                + stored[base + 16:base + 24]
                + stored[base + 8:base + 16]
                + stored[base + 24:base + 32]
            )
    elif len(data) >= 64:
        color_count = 16
        raw = data[:64]
        colors = [tuple(raw[index:index + 4]) for index in range(0, 64, 4)]
    else:
        raise ValueError("Type-13 palette is smaller than the 16-color PS2 CLUT format.")
    return color_count, [(r, g, b, min(255, a * 2)) for r, g, b, a in colors]


def decode_palette(data, entry_name="Palette"):
    color_count, colors = _decode_colors(bytes(data))
    lines = [
        "# Pipeworks PS2 type-13 palette",
        f"# Entry={entry_name}",
        "# This is a CLUT used by an indexed type-9 texture, not a standalone texture.",
        "# Format: #RRGGBBAA",
        "",
        "palette",
        "{",
        f"    ColorCount = {color_count};",
        "",
        "    colors",
        "    {",
    ]
    for index, (red, green, blue, alpha) in enumerate(colors):
        lines.append(f"        [{index:03d}] = #{red:02X}{green:02X}{blue:02X}{alpha:02X};")
    lines.extend(("    }", "}", ""))
    return "\n".join(lines)


def encode_palette(text, original):
    original = bytes(original)
    color_count, _colors = _decode_colors(original)
    parsed = {}
    for line in str(text).splitlines():
        match = COLOR_RE.match(line)
        if not match:
            continue
        index = int(match.group(1))
        if index in parsed:
            raise ValueError(f"Duplicate palette index {index}.")
        value = match.group(2)
        parsed[index] = tuple(int(value[pos:pos + 2], 16) for pos in range(0, 8, 2))
    expected = set(range(color_count))
    missing = sorted(expected - set(parsed))
    extra = sorted(set(parsed) - expected)
    if missing:
        raise ValueError(f"Missing palette index {missing[0]}.")
    if extra:
        raise ValueError(f"Palette index {extra[0]} exceeds the {color_count}-color CLUT.")
    colors = [parsed[index] for index in range(color_count)]
    if color_count == 256:
        stored = [(0, 0, 0, 0)] * 256
        for base in range(0, 256, 32):
            chunk = colors[base:base + 32]
            stored[base:base + 8] = chunk[0:8]
            stored[base + 8:base + 16] = chunk[16:24]
            stored[base + 16:base + 24] = chunk[8:16]
            stored[base + 24:base + 32] = chunk[24:32]
    else:
        stored = colors
    encoded = bytearray()
    for red, green, blue, alpha in stored:
        encoded.extend((red, green, blue, max(0, min(128, round(alpha / 2)))))
    used_size = color_count * 4
    return bytes(encoded) + original[used_size:]
