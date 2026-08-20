#!/usr/bin/env python3
"""
Pipeworks PWK VM module (.pvm) inspection helper.

This is intentionally conservative: it identifies GC/Wii PWK VM script modules,
parses the stable header/section table, extracts string pools and symbol-like
names, and emits an editable-looking text report without claiming bytecode
round-trip support yet.
"""
from __future__ import annotations

import argparse
import ast
import re
import struct
from dataclasses import dataclass
from pathlib import Path


MAGIC_PREFIX = b"PWK Virtual machine module "
HEADER_SIZE = 0x80
SECTION_TABLE_START = 0x38
SECTION_COUNT = 9

# Recovered from Godzilla3.elf:
#   GetPVOpSize__FPUc @ 0x801D4120
# It masks opcodes with 0x7F. 0x6C and 0x6D are special variable-width
# records; 0x64..0x7A use the table below, with 0x6C/0x6D handled first.
PV_FIXED_OP_SIZES = {
    0x64: 3,
    0x65: 2,
    0x66: 5,
    0x67: 5,
    0x68: 1,
    0x69: 5,
    0x6A: 5,
    0x6B: 2,
    0x6E: 3,
    0x6F: 5,
    0x70: 5,
    0x71: 5,
    0x72: 7,
    0x73: 7,
    0x74: 3,
    0x75: 3,
    0x76: 1,
    0x77: 1,
    0x78: 1,
    0x79: 1,
    0x7A: 1,
}

PV_6D_SUBTYPE_SIZES = {
    0: 7,
    1: 7,
    2: 3,
    3: 3,
    4: 7,
    5: 3,
    6: 7,
    7: 3,
}


@dataclass(frozen=True)
class PvmSection:
    index: int
    offset: int
    size: int

    @property
    def end(self) -> int:
        return self.offset + self.size


@dataclass(frozen=True)
class PvmModule:
    data: bytes
    version_text: str
    marker: int
    total_size: int
    sections: tuple[PvmSection, ...]


@dataclass(frozen=True)
class PvmEditableValue:
    file_offset: int
    code_offset: int
    op: int
    kind: str
    value: int | float
    raw: bytes
    note: str = ""
    tag: int | None = None


@dataclass(frozen=True)
class PvmTypedValue:
    file_offset: int
    entry_index: int
    type_name: str
    name: str
    value: int | float | str
    raw_value: int


@dataclass(frozen=True)
class PvmInstruction:
    code_offset: int
    file_offset: int
    op: int
    size: int
    raw: bytes
    text: str


PV_OPERATOR_MODES = {
    0: "binary_type_op",
    1: "binary_type_op",
    2: "truth_test",
    3: "copy",
    4: "typed_compare",
    5: "noop",
    6: "binary_type_store",
    7: "noop",
}

def is_pwk_vm_module(data: bytes) -> bool:
    return len(data) >= HEADER_SIZE and data.startswith(MAGIC_PREFIX)


def parse_pvm(data: bytes) -> PvmModule:
    if not is_pwk_vm_module(data):
        raise ValueError("Not a PWK Virtual machine module PVM.")
    version_text = data[:0x30].decode("ascii", errors="replace").rstrip()
    marker = struct.unpack_from(">I", data, 0x30)[0]
    total_size = struct.unpack_from(">I", data, 0x34)[0]
    if total_size != len(data):
        raise ValueError(f"Header size field is 0x{total_size:X}, file is 0x{len(data):X}.")

    sections = []
    for index in range(SECTION_COUNT):
        entry = SECTION_TABLE_START + index * 8
        offset, size = struct.unpack_from(">II", data, entry)
        if offset < HEADER_SIZE or offset + size > len(data):
            raise ValueError(
                f"Section {index} range 0x{offset:X}+0x{size:X} is outside the file."
            )
        sections.append(PvmSection(index, offset, size))
    return PvmModule(data, version_text, marker, total_size, tuple(sections))


def load_pvm(path: Path) -> PvmModule:
    return parse_pvm(path.read_bytes())


def _clean_pool_string(raw: bytes) -> str:
    text = raw.decode("latin-1", errors="replace")
    # Many modules pad pools with literal 0x7A bytes ('z'). Keep meaningful
    # identifiers intact, but do not report pure padding as a symbol.
    if set(text) <= {"z"}:
        return ""
    return text


def extract_null_strings(data: bytes, base_offset: int = 0, min_len: int = 1):
    strings = []
    start = 0
    for index, byte in enumerate(data + b"\0"):
        if byte != 0:
            continue
        if index > start:
            raw = data[start:index]
            if len(raw) >= min_len and all(32 <= ch < 127 for ch in raw):
                text = _clean_pool_string(raw)
                if text:
                    strings.append((base_offset + start, text))
        start = index + 1
    return strings


def section_data(module: PvmModule, index: int) -> bytes:
    section = module.sections[index]
    return module.data[section.offset:section.end]


def pvm_op_size(code: bytes, offset: int) -> int:
    if offset >= len(code):
        return 0
    op = code[offset] & 0x7F
    if op == 0x6D:
        subtype = code[offset + 2] if offset + 2 < len(code) else 0
        return PV_6D_SUBTYPE_SIZES.get(subtype, 3)
    if op == 0x6C:
        # The runtime aligns (ip + 4) down to a 4-byte boundary and reads a
        # u16 record count from that aligned word. The exact formula includes
        # the opcode value, which makes these records act like table blocks.
        if offset + 5 >= len(code):
            return 1
        aligned = (offset + 4) & ~3
        if aligned + 2 <= len(code):
            count = int.from_bytes(code[aligned:aligned + 2], "big")
            if count > 0:
                return min(len(code) - offset, ((count - 1) * 8) + op + 12)
        return 1
    return PV_FIXED_OP_SIZES.get(op, 1)


def pvm_code_offsets(module: PvmModule) -> list[int]:
    blob = section_data(module, 3)
    if len(blob) < 8:
        return []
    count = int.from_bytes(blob[0:4], "big")
    offsets = []
    pos = 8
    for _ in range(min(count, (len(blob) - pos) // 4)):
        value = int.from_bytes(blob[pos:pos + 4], "big")
        if 0 <= value < module.sections[0].size:
            offsets.append(value)
        pos += 4
    return offsets


def format_bytecode_preview(module: PvmModule, max_ops: int = 180) -> str:
    code = section_data(module, 0)
    entry_offsets = set(pvm_code_offsets(module))
    lines = []
    lines.append("[bytecode preview]")
    if entry_offsets:
        lines.append("; section 3 code offsets: " + ", ".join(f"0x{value:04X}" for value in sorted(entry_offsets)[:64]))
        if len(entry_offsets) > 64:
            lines.append(f"; ... {len(entry_offsets) - 64} more")
    lines.append("; op byte is masked with 0x7F by the runtime; sizes come from GetPVOpSize where known.")

    offset = 0
    ops = 0
    while offset < len(code) and ops < max_ops:
        mark = ">" if offset in entry_offsets else " "
        size = max(1, pvm_op_size(code, offset))
        raw = code[offset:offset + size]
        op = code[offset] & 0x7F
        raw_display = raw.hex(" ")
        if len(raw) > 16:
            raw_display = raw[:16].hex(" ") + f" ... ({len(raw)} bytes)"
        operands = raw[1:].hex(" ") if 1 < len(raw) <= 16 else ""
        label = f"op_0x{op:02X}"
        if op == 0x6C:
            label = "table_6C"
        elif op == 0x6D:
            subtype = code[offset + 2] if offset + 2 < len(code) else 0
            label = f"op_6D{subtype}"
        lines.append(f"{mark} +0x{offset:04X}: {raw_display:<48} {label:<10} size={size:<3} {operands}")
        offset += size
        ops += 1
    if offset < len(code):
        lines.append(f"; preview stopped at +0x{offset:04X} of 0x{len(code):X}")
    return "\n".join(lines)


def strings_by_section(module: PvmModule):
    return {
        section.index: extract_null_strings(
            module.data[section.offset:section.end],
            section.offset,
        )
        for section in module.sections
    }


def indexed_pool(module: PvmModule, section_index: int) -> list[str]:
    return [text for _offset, text in extract_null_strings(
        section_data(module, section_index),
        module.sections[section_index].offset,
    )]


def _u24(data: bytes) -> int:
    return int.from_bytes(data, "big")


def _symbol_note(value: int, symbols: list[str], debug: list[str]) -> str:
    parts = []
    if 0 <= value < len(symbols):
        parts.append(f"symbol[{value}]={symbols[value]!r}")
    if 0 <= value < len(debug):
        parts.append(f"debug[{value}]={debug[value]!r}")
    return "; ".join(parts)


def _looks_like_name(text: str) -> bool:
    if not text or text == "<main>":
        return False
    upper = text.upper()
    if upper.endswith((".H", ".SCR")):
        return False
    if text.startswith("temp_"):
        return False
    return bool(re.match(r"^[A-Za-z_][A-Za-z0-9_:]*$", text))


def _pool_name(index: int, symbols: list[str], debug: list[str]) -> str:
    candidates = []
    if 0 <= index < len(symbols):
        candidates.append(symbols[index])
    if 0 <= index < len(debug):
        candidates.append(debug[index])
    for candidate in candidates:
        if _looks_like_name(candidate):
            return candidate
    for candidate in candidates:
        if candidate and candidate != "<main>":
            return candidate
    return f"ref_{index}"


def _code_note(value: int, code_size: int) -> str:
    if 0 <= value < code_size:
        return f"code_target={value}"
    return ""


def _instruction_offsets(module: PvmModule) -> list[int]:
    code = section_data(module, 0)
    offsets: list[int] = []
    offset = 0
    valid_ops = set(PV_FIXED_OP_SIZES) | {0x6C, 0x6D}

    while offset < len(code):
        op = code[offset] & 0x7F
        if op not in valid_ops:
            offset += 1
            continue
        size = max(1, pvm_op_size(code, offset))
        if offset + size > len(code):
            break
        offsets.append(offset)
        if op == 0x6C and offset + 8 < len(code):
            # 0x6C marks a frame/table header. The VM bytecode for that frame
            # can follow the 8-byte header, but some frames contain metadata
            # there instead. Only enter the body when it begins with a VM op.
            body = offset + 8
            if (code[body] & 0x7F) in valid_ops:
                offset = body
            else:
                offset += size
        else:
            offset += size
    return offsets


def _decode_table_6c(code_offset: int, raw: bytes) -> str:
    if len(raw) < 8:
        return "enter_call_frame(table=bad)"
    aligned = ((code_offset + 4) & ~3) - code_offset
    count = int.from_bytes(raw[aligned:aligned + 2], "big") if aligned + 2 <= len(raw) else 0
    return f"enter_call_frame locals={count}"


def decode_pvm_instructions(module: PvmModule) -> list[PvmInstruction]:
    code = section_data(module, 0)
    code_base = module.sections[0].offset
    symbols = indexed_pool(module, 6)
    debug = indexed_pool(module, 8)
    entry_offsets = set(pvm_code_offsets(module))
    out: list[PvmInstruction] = []

    for offset in _instruction_offsets(module):
        op = code[offset] & 0x7F
        size = max(1, pvm_op_size(code, offset))
        if offset + size > len(code):
            size = len(code) - offset
        raw = code[offset:offset + size]
        text = f"TODO_decode_op_{op}"

        if op == 0x64 and len(raw) >= 3:
            value = int.from_bytes(raw[1:3], "big")
            text = f"push_frame_ref local[{value}]"
        elif op == 0x65 and len(raw) >= 2:
            text = f"push_stack_ref relative[{raw[1]}]"
        elif op == 0x66 and len(raw) >= 5:
            tag = raw[1]
            index = _u24(raw[2:5])
            name = _pool_name(index, symbols, debug)
            text = f"push_copy {name} ; tag={tag}, index={index}"
        elif op == 0x67 and len(raw) >= 5:
            tag = raw[1]
            index = _u24(raw[2:5])
            name = _pool_name(index, symbols, debug)
            text = f"push_ref {name} ; tag={tag}, index={index}"
        elif op == 0x68:
            text = "push_null"
        elif op == 0x69 and len(raw) >= 5:
            tag = raw[1]
            target = _u24(raw[2:5])
            text = f"push_code_ptr loc_{target} ; tag={tag}"
        elif op == 0x6A and len(raw) >= 5:
            tag = raw[1]
            value = _u24(raw[2:5])
            text = f"push_int {value} ; tag={tag}"
        elif op == 0x6B and len(raw) >= 2:
            text = f"drop {raw[1]}"
        elif op == 0x6C:
            text = _decode_table_6c(offset, raw)
        elif op == 0x6D and len(raw) >= 3:
            token = raw[1]
            mode_id = raw[2]
            mode = PV_OPERATOR_MODES.get(mode_id, f"mode_{mode_id}")
            extra = ""
            if len(raw) >= 7:
                tag = raw[3]
                index = _u24(raw[4:7])
                extra = f", tag={tag}, index={index}"
            text = f"apply_operator token={token}, mode={mode}{extra}"
        elif op == 0x6E and len(raw) >= 3:
            member = int.from_bytes(raw[1:3], "big")
            text = f"call_member pop_object.{_pool_name(member, symbols, debug)}"
        elif op == 0x6F and len(raw) >= 5:
            tag = raw[1]
            target = _u24(raw[2:5])
            text = f"jump_if_true loc_{target} ; tag={tag}"
        elif op == 0x70 and len(raw) >= 5:
            tag = raw[1]
            target = _u24(raw[2:5])
            text = f"jump_if_false loc_{target} ; tag={tag}"
        elif op == 0x71 and len(raw) >= 5:
            tag = raw[1]
            target = _u24(raw[2:5])
            text = f"jump loc_{target} ; tag={tag}"
        elif op == 0x72 and len(raw) >= 7:
            tag = raw[1]
            target = _u24(raw[2:5])
            local = int.from_bytes(raw[5:7], "big")
            text = f"set_local local[{local}] = stack.top; call_virtual24 loc_{target} ; tag={tag}"
        elif op == 0x73 and len(raw) >= 7:
            tag = raw[1]
            target = _u24(raw[2:5])
            local = int.from_bytes(raw[5:7], "big")
            text = f"set_local local[{local}] = stack.top; call_virtual28 loc_{target} ; tag={tag}"
        elif op == 0x74 and len(raw) >= 3:
            local = int.from_bytes(raw[1:3], "big")
            text = f"set_local local[{local}] = stack.top"
        elif op == 0x75 and len(raw) >= 3:
            member = int.from_bytes(raw[1:3], "big")
            text = f"call_member pop_object.{_pool_name(member, symbols, debug)}"
        elif op == 0x76:
            text = "compare stack[-1], stack[0]"
        elif op == 0x77:
            text = "return_value stack.top"
        elif op == 0x78:
            text = "return"
        elif op == 0x79:
            text = "yield"
        elif op == 0x7A:
            text = "end"

        out.append(PvmInstruction(offset, code_base + offset, op, size, raw, text))
    return out


def format_pvm_code(module: PvmModule) -> str:
    entry_offsets = set(pvm_code_offsets(module))
    lines = ["[Code]"]
    lines.append("# Decoded VM instructions. Numeric literals are decimal; loc_N labels are section-0 code offsets.")
    for inst in decode_pvm_instructions(module):
        label = f"loc_{inst.code_offset}: " if inst.code_offset in entry_offsets else ""
        lines.append(f"{label}{inst.text}")
    return "\n".join(lines)


def extract_editable_values(module: PvmModule) -> list[PvmEditableValue]:
    """Return same-size patchable values from section 0 bytecode.

    This intentionally exposes operands, not source syntax. The opcode meanings
    are still being named, but these rows are already useful for controlled
    numeric edits and byte-for-byte patching.
    """
    code = section_data(module, 0)
    code_base = module.sections[0].offset
    symbols = indexed_pool(module, 6)
    debug = indexed_pool(module, 8)
    out: list[PvmEditableValue] = []

    for offset in _instruction_offsets(module):
        op = code[offset] & 0x7F
        size = pvm_op_size(code, offset)
        if size <= 1 or offset + size > len(code):
            continue
        raw = code[offset:offset + size]

        if op in (0x65,):
            value = raw[1]
            out.append(PvmEditableValue(code_base + offset + 1, offset, op, "u8", value, raw[1:2]))
        elif op in (0x64, 0x6E, 0x74, 0x75):
            value = int.from_bytes(raw[1:3], "big")
            note = ""
            if op in (0x6E, 0x75):
                note = _symbol_note(value, symbols, debug)
            out.append(PvmEditableValue(code_base + offset + 1, offset, op, "u16", value, raw[1:3], note))
        elif op in (0x66, 0x67, 0x69, 0x6A, 0x6F, 0x70, 0x71):
            tag = raw[1]
            value = _u24(raw[2:5])
            note = ""
            if op in (0x66, 0x67):
                note = _symbol_note(value, symbols, debug)
            elif op in (0x69, 0x6F, 0x70, 0x71):
                note = _code_note(value, len(code))
            elif op == 0x6A:
                note = "literal/call-arg candidate"
            out.append(PvmEditableValue(code_base + offset + 2, offset, op, "u24", value, raw[2:5], note, tag=tag))
        elif op in (0x72, 0x73) and len(raw) >= 7:
            tag = raw[1]
            target = _u24(raw[2:5])
            local = int.from_bytes(raw[5:7], "big")
            note = _code_note(target, len(code)) or _symbol_note(target, symbols, debug)
            out.append(PvmEditableValue(code_base + offset + 2, offset, op, "u24", target, raw[2:5], note, tag=tag))
            out.append(PvmEditableValue(code_base + offset + 5, offset, op, "u16", local, raw[5:7], "local slot", tag=tag))
        elif op == 0x6D:
            subtype = raw[2] if len(raw) > 2 else -1
            if len(raw) >= 3:
                out.append(PvmEditableValue(code_base + offset + 1, offset, op, "u8", raw[1], raw[1:2], f"6D subtype={subtype}"))
            if len(raw) >= 7:
                tag = raw[3]
                value = _u24(raw[4:7])
                note = _symbol_note(value, symbols, debug) or _code_note(value, len(code))
                out.append(PvmEditableValue(code_base + offset + 4, offset, op, "u24", value, raw[4:7], note, tag=tag))
    return out


def _name_from_note(note: str) -> str | None:
    symbol_match = re.search(r"symbol\[\d+\]='([^']+)'", note)
    debug_match = re.search(r"debug\[\d+\]='([^']+)'", note)
    for match in (symbol_match, debug_match):
        if not match:
            continue
        name = match.group(1)
        upper = name.upper()
        if name == "<main>" or upper.endswith((".H", ".SCR")):
            continue
        return name
    return None


def _safe_key(text: str) -> str:
    text = re.sub(r"[^A-Za-z0-9_.:]+", "_", text.strip())
    text = text.strip("_")
    return text or "value"


def _value_key(item: PvmEditableValue) -> str:
    name = _name_from_note(item.note)
    if name:
        return _safe_key(name)
    code_match = re.search(r"code_target=(\d+)", item.note)
    if code_match:
        return f"branch_target_{int(code_match.group(1), 10)}"
    if item.op == 0x6A:
        return f"literal_{item.code_offset}"
    if item.op == 0x6D:
        return f"operator_arg_{item.code_offset}"
    if item.op in (0x66, 0x67, 0x6E, 0x75):
        return f"ref_{item.value}"
    if item.op == 0x64:
        return f"frame_ref_{item.code_offset}"
    if item.op == 0x65:
        return f"relative_ref_{item.code_offset}"
    if item.op == 0x74:
        return f"set_local_{item.code_offset}"
    if item.op in (0x72, 0x73):
        return f"assign_call_arg_{item.code_offset}"
    return f"value_{item.code_offset}"


def _display_type(item: PvmEditableValue) -> str:
    if item.op == 0x6A:
        return "int"
    return item.kind


def _display_key(item: PvmEditableValue) -> str:
    if item.op == 0x6A:
        return f"literal_{item.code_offset}"
    return _value_key(item)


def _display_typed_value(type_name: str, raw_value: int, symbols: list[str], debug: list[str]) -> int | float | str:
    if type_name == "float":
        value = struct.unpack(">f", raw_value.to_bytes(4, "big"))[0]
        return value
    if type_name == "string":
        for index, value in enumerate(symbols):
            if index == raw_value:
                return value
        for index, value in enumerate(debug):
            if index == raw_value:
                return value
        return str(raw_value)
    signed = raw_value - 0x100000000 if raw_value & 0x80000000 else raw_value
    return signed


def _cstr(blob: bytes, offset: int) -> str:
    if offset < 0 or offset >= len(blob):
        return ""
    end = blob.find(b"\0", offset)
    if end < 0:
        end = len(blob)
    return blob[offset:end].decode("latin-1", errors="replace")


def _type_names(module: PvmModule) -> list[str]:
    blob = section_data(module, 4)
    strings = section_data(module, 6)
    if len(blob) < 4:
        return []
    count = struct.unpack_from(">I", blob, 0)[0]
    names: list[str] = []
    offset = 4
    for _ in range(count):
        if offset + 8 > len(blob):
            break
        size = struct.unpack_from(">H", blob, offset + 2)[0]
        name_offset = struct.unpack_from(">I", blob, offset + 4)[0]
        names.append(_cstr(strings, name_offset))
        if size < 8 or offset + size > len(blob):
            break
        offset += size
    return names


def _decode_initial_value(type_name: str, raw_value: int, strings: bytes) -> int | float | str | None:
    if type_name == "int":
        return raw_value - 0x100000000 if raw_value & 0x80000000 else raw_value
    if type_name == "float":
        return struct.unpack(">f", raw_value.to_bytes(4, "big"))[0]
    if type_name == "string":
        return _cstr(strings, raw_value)
    return None


def _looks_like_value_label(value: object) -> bool:
    if not isinstance(value, str) or not value:
        return False
    if value == "<main>" or value.upper().endswith((".H", ".SCR")):
        return False
    if "\n" in value or "\r" in value:
        return False
    return any(ch.isalpha() for ch in value)


def extract_typed_values(module: PvmModule) -> list[PvmTypedValue]:
    type_names = _type_names(module)
    strings = section_data(module, 6)
    blob = section_data(module, 1)
    rows: list[PvmTypedValue] = []

    if len(blob) < 4:
        return rows
    count = struct.unpack_from(">H", blob, 0)[0]
    max_count = (len(blob) - 4) // 8
    if count > max_count:
        return rows

    pending_labels: list[str] = []
    for entry_index in range(count):
        offset = 4 + entry_index * 8
        type_index = struct.unpack_from(">H", blob, offset)[0]
        if type_index >= len(type_names):
            continue
        type_name = type_names[type_index]
        raw_value = struct.unpack_from(">I", blob, offset + 4)[0]
        value = _decode_initial_value(type_name, raw_value, strings)
        if value is None:
            pending_labels.clear()
            continue

        file_offset = module.sections[1].offset + offset + 4
        if type_name == "string":
            name = _safe_key(f"text_{value}") if value else f"text_{entry_index:03d}"
            row = PvmTypedValue(file_offset, entry_index, type_name, name, value, raw_value)
            rows.append(row)
            if _looks_like_value_label(value):
                pending_labels.append(value)
            continue

        if pending_labels:
            name = _safe_key(pending_labels.pop(0))
        else:
            name = f"value_{entry_index:03d}"
        rows.append(PvmTypedValue(file_offset, entry_index, type_name, name, value, raw_value))

    return rows


def _is_user_value(item: PvmEditableValue) -> bool:
    return item.op == 0x6A


def _row_comment(item: PvmEditableValue) -> str:
    parts = [f"op={item.op}", f"code={item.code_offset}"]
    if item.tag is not None:
        parts.append(f"tag={item.tag}")
    if item.note:
        note = re.sub(r"\s*;\s*", ", ", item.note)
        parts.append(note)
    return " # " + "; ".join(parts)


def format_editable_values(module: PvmModule, limit: int | None = None) -> str:
    typed_values = extract_typed_values(module)
    values = typed_values if typed_values else [item for item in extract_editable_values(module) if _is_user_value(item)]
    lines = []
    lines.append("[Rows]")
    lines.append("Offset     | Type | Name                    | Value")
    shown = values if limit is None else values[:limit]
    for item in shown:
        if isinstance(item, PvmTypedValue):
            value = repr(item.value) if isinstance(item.value, (float, str)) else str(item.value)
            lines.append(f"@0x{item.file_offset:06X} | {item.type_name:<6} | {item.name:<23} | {value}")
        else:
            value = str(item.value) if isinstance(item.value, int) else repr(item.value)
            lines.append(f"@0x{item.file_offset:06X} | {_display_type(item):<6} | {_display_key(item):<23} | {value}")
    if limit is not None and len(values) > limit:
        lines.append(f"# ... {len(values) - limit} more value rows hidden")
    lines.append(f"# Total rows: {len(values)}")
    return "\n".join(lines)


def source_names(strings):
    result = []
    for _offset, text in strings:
        upper = text.upper()
        if upper.endswith((".SCR", ".H")) or text == "<main>":
            result.append(text)
    return result


def likely_functions(strings):
    names = []
    for _offset, text in strings:
        if text == "<main>" or "::" in text:
            names.append(text)
            continue
        if re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", text) and not text.startswith("temp_"):
            if text[:1].islower() or text[:1].isupper():
                names.append(text)
    return names


def table_summary(module: PvmModule, index: int) -> str:
    blob = section_data(module, index)
    if len(blob) < 4:
        return ""
    first_u32 = struct.unpack_from(">I", blob, 0)[0]
    words = [struct.unpack_from(">I", blob, off)[0] for off in range(0, min(len(blob), 32), 4)]
    return (
        f"first_u32=0x{first_u32:08X} "
        f"words[0..{len(words)-1}]="
        + " ".join(f"{word:08X}" for word in words)
    )


def _format_pvm_diagnostics(module: PvmModule) -> str:
    by_section = strings_by_section(module)
    all_strings = [item for values in by_section.values() for item in values]
    debug_strings = by_section.get(8, [])
    symbol_strings = by_section.get(6, [])

    lines = []
    src = source_names(debug_strings or all_strings)
    if src:
        lines.append("[source/debug files]")
        for text in src:
            lines.append(text)
        lines.append("")

    funcs = likely_functions(debug_strings)
    if funcs:
        lines.append("[debug/local names]")
        for text in funcs:
            lines.append(text)
        lines.append("")

    symbols = likely_functions(symbol_strings)
    if symbols:
        lines.append("[symbols/imports/fields]")
        for text in symbols:
            lines.append(text)
        lines.append("")

    lines.append("[string pools]")
    for index in (6, 8):
        values = by_section[index]
        if not values:
            continue
        lines.append(f"; section {index}, {len(values)} string(s)")
        for offset, text in values:
            escaped = text.replace("\\", "\\\\").replace("\n", "\\n")
        lines.append(f"@0x{offset:06X} {escaped}")
        lines.append("")

    lines.append(format_pvm_code(module))
    lines.append("")

    lines.append(format_bytecode_preview(module))
    lines.append("")

    lines.append("[table previews]")
    for index in range(1, 6):
        lines.append(f"; section {index}: {table_summary(module, index)}")
    lines.append(f"; section 7: {table_summary(module, 7)}")
    return "\n".join(lines).rstrip()


def format_pvm_report(module: PvmModule, path: Path | None = None, include_tables: bool = False) -> str:
    lines = []
    lines.append("# PVM text export")
    if path is not None:
        lines.append(f"# SourcePVM={path}")
    lines.append(f"# PVM={path.name if path is not None else ''}")
    lines.append(f"# Version={module.version_text}")
    lines.append("# Edit the Value column on @ rows, then Save or Convert back to PVM.")
    lines.append("")
    lines.append(format_editable_values(module))
    lines.append("")

    if include_tables:
        lines.append("[Sections]")
        for section in module.sections:
            lines.append(
                f"{section.index}: offset=0x{section.offset:06X} "
                f"size=0x{section.size:06X} end=0x{section.end:06X}"
            )
        lines.append("")
        lines.append(_format_pvm_diagnostics(module))
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def pvm_to_editable(data: bytes, path: Path | None = None) -> str:
    return format_pvm_report(parse_pvm(data), path)


def _parse_int_value(text: str) -> int:
    text = re.split(r"\s*(?:#|;)", text.strip(), maxsplit=1)[0].strip()
    if text.lower().startswith("0x"):
        return int(text, 16)
    return int(text, 10)


def _parse_string_edit_value(value_text: str) -> str:
    value_text = value_text.strip()
    try:
        unquoted = ast.literal_eval(value_text)
    except (SyntaxError, ValueError):
        unquoted = value_text.strip("\"'")
    if not isinstance(unquoted, str):
        raise ValueError(f"String value must be text, got {type(unquoted).__name__}.")
    return unquoted


def _parse_typed_raw(
    module: PvmModule,
    type_name: str,
    value_text: str,
    original_value: int | float | str | None = None,
    original_raw: int | None = None,
) -> int:
    if type_name == "float":
        value_text = re.split(r"\s*(?:#|;)", value_text.strip(), maxsplit=1)[0].strip()
        return struct.unpack(">I", struct.pack(">f", float(value_text)))[0]
    if type_name == "string":
        unquoted = _parse_string_edit_value(value_text)
        pool = section_data(module, 6)
        for offset, text in extract_null_strings(pool, 0):
            if text == unquoted:
                return offset
        if original_raw is not None:
            original_text = _cstr(pool, original_raw)
            if unquoted == original_value:
                return original_raw
            if len(unquoted.encode("latin-1")) <= len(original_text.encode("latin-1")):
                return original_raw
            raise ValueError(
                f"{unquoted!r} is not in this PVM string pool and is too long for "
                f"the original {original_text!r} string slot."
            )
        return _parse_int_value(value_text)
    value_text = re.split(r"\s*(?:#|;)", value_text.strip(), maxsplit=1)[0].strip()
    return _parse_int_value(value_text) & 0xFFFFFFFF


def _append_pvm_string(data: bytearray, module: PvmModule, value: str) -> int:
    encoded = value.encode("latin-1")
    string_section = module.sections[6]
    insert_at = string_section.end
    string_offset = string_section.size
    payload = encoded + b"\0"
    data[insert_at:insert_at] = payload
    delta = len(payload)
    struct.pack_into(">I", data, 0x34, len(data))
    for index, section in enumerate(module.sections):
        entry = SECTION_TABLE_START + index * 8
        if index == 6:
            struct.pack_into(">I", data, entry + 4, section.size + delta)
        elif index > 6:
            struct.pack_into(">I", data, entry, section.offset + delta)
    return string_offset


def _editable_maps(module: PvmModule):
    typed_allowed = {
        (item.file_offset, item.type_name): item
        for item in extract_typed_values(module)
    }
    allowed = {
        (item.file_offset, item.kind): item
        for item in extract_editable_values(module)
    }
    return typed_allowed, allowed


def editable_to_pvm(text: str, original_data: bytes) -> bytes:
    data = bytearray(original_data)
    if not is_pwk_vm_module(data):
        raise ValueError("Original data is not a PWK VM PVM.")
    module = parse_pvm(bytes(data))
    typed_allowed, allowed = _editable_maps(module)
    old_row_re = re.compile(
        r"^@0x([0-9A-Fa-f]+)\s+.*?\bkind=(u8|u16|u24)\b.*?\bvalue=([+-]?(?:0x[0-9A-Fa-f]+|\d+))"
    )
    new_row_re = re.compile(
        r"^@0x([0-9A-Fa-f]+)\s+(u8|u16|u24)\s+.+?\s+=\s+([+-]?(?:0x[0-9A-Fa-f]+|\d+))"
    )
    table_row_re = re.compile(
        r"^@0x([0-9A-Fa-f]+)\s*\|\s*([A-Za-z0-9_]+)\s*\|\s*.+?\s*\|\s*(.+?)\s*$"
    )
    editable_lines: list[re.Match[str]] = []
    for line in text.splitlines():
        stripped = line.strip()
        match = old_row_re.match(stripped) or new_row_re.match(stripped) or table_row_re.match(stripped)
        if match:
            editable_lines.append(match)
    editable_lines.sort(key=lambda item: int(item.group(1), 16))

    patched = 0
    string_insert_threshold = module.sections[6].end
    inserted_string_bytes = 0
    for match in editable_lines:
        original_file_offset = int(match.group(1), 16)
        file_offset = original_file_offset + (inserted_string_bytes if original_file_offset >= string_insert_threshold else 0)
        kind = match.group(2)
        typed_item = typed_allowed.get((file_offset, kind))
        if typed_item is not None:
            if kind == "string":
                string_patch_value = _parse_string_edit_value(match.group(3))
                pool = section_data(module, 6)
                existing_offset = next(
                    (offset for offset, text_value in extract_null_strings(pool, 0) if text_value == string_patch_value),
                    None,
                )
                if existing_offset is not None:
                    raw_value = existing_offset
                elif string_patch_value == typed_item.value:
                    raw_value = typed_item.raw_value
                else:
                    old_bytes = str(typed_item.value).encode("latin-1")
                    new_bytes = string_patch_value.encode("latin-1")
                    if len(new_bytes) <= len(old_bytes):
                        pool_start = module.sections[6].offset + typed_item.raw_value
                        old_slot = old_bytes + b"\0"
                        new_slot = new_bytes + (b"\0" * (len(old_bytes) - len(new_bytes) + 1))
                        if data[pool_start:pool_start + len(old_slot)] != old_slot:
                            raise ValueError(f"Original string bytes changed at 0x{pool_start:X}; refusing stale patch.")
                        data[pool_start:pool_start + len(old_slot)] = new_slot
                        module = parse_pvm(bytes(data))
                        typed_allowed, allowed = _editable_maps(module)
                        patched += 1
                        continue
                    before_len = len(data)
                    raw_value = _append_pvm_string(data, module, string_patch_value)
                    inserted_string_bytes += len(data) - before_len
                    module = parse_pvm(bytes(data))
                    typed_allowed, allowed = _editable_maps(module)
                    typed_item = typed_allowed.get((file_offset, kind))
                    if typed_item is None:
                        raise ValueError(f"Could not refresh PVM string row at 0x{file_offset:X} after extending string pool.")
            else:
                raw_value = _parse_typed_raw(
                    module,
                    kind,
                    match.group(3),
                    original_value=typed_item.value,
                    original_raw=typed_item.raw_value,
                )
            new_raw = raw_value.to_bytes(4, "big")
            if data[file_offset:file_offset + 4] != typed_item.raw_value.to_bytes(4, "big") and raw_value != typed_item.raw_value:
                raise ValueError(f"Original bytes changed at 0x{file_offset:X}; refusing stale patch.")
            if raw_value != typed_item.raw_value:
                data[file_offset:file_offset + 4] = new_raw
                patched += 1
            continue

        value = _parse_int_value(match.group(3))
        if kind == "int":
            kind = next((candidate.kind for candidate in allowed.values() if candidate.file_offset == file_offset), kind)
        item = allowed.get((file_offset, kind))
        if item is None:
            raise ValueError(f"Unknown or non-editable value row at 0x{file_offset:X}.")
        width = {"u8": 1, "u16": 2, "u24": 3}[kind]
        max_value = (1 << (width * 8)) - 1
        if not 0 <= value <= max_value:
            raise ValueError(f"Value {value} does not fit {kind} at 0x{file_offset:X}.")
        new_raw = value.to_bytes(width, "big")
        if data[file_offset:file_offset + width] != item.raw and new_raw != item.raw:
            raise ValueError(f"Original bytes changed at 0x{file_offset:X}; refusing stale patch.")
        if new_raw != item.raw:
            data[file_offset:file_offset + width] = new_raw
            patched += 1
    if patched == 0:
        # No-op saves are allowed; they keep bundle-entry workflows calm.
        return bytes(data)
    parse_pvm(bytes(data))
    return bytes(data)


def dump_pvm(path: Path, out: Path | None = None, include_tables: bool = False) -> Path:
    module = load_pvm(path)
    text = format_pvm_report(module, path, include_tables=include_tables)
    out = out or path.with_suffix(path.suffix + ".txt")
    out.write_text(text, encoding="utf-8", newline="\n")
    return out


def main(argv=None):
    parser = argparse.ArgumentParser(description="Inspect Pipeworks PWK VM .pvm script modules")
    parser.add_argument("input", type=Path)
    parser.add_argument("-o", "--output", type=Path)
    parser.add_argument("--verbose", action="store_true", help="append symbol pools and bytecode diagnostics")
    args = parser.parse_args(argv)
    made = dump_pvm(args.input, args.output, include_tables=args.verbose)
    print(f"Wrote PVM report: {made}")


if __name__ == "__main__":
    main()
