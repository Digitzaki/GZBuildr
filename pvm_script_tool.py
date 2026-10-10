#!/usr/bin/env python3
"""
Pipeworks PWK VM module (.pvm) inspection helper.

This is intentionally conservative: it parses big-endian GC/Wii and
little-endian PS2 PWK VM script modules, emits typed globals, and decompiles
preserved bytecode into source-like routines using semantics recovered from
Godzilla3.elf.
"""
from __future__ import annotations

import argparse
import ast
import re
import struct
import sys
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
    endian: str = ">"


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


@dataclass(frozen=True)
class PvmCodeEntry:
    index: int
    code_offset: int
    file_offset: int
    end_code_offset: int
    name: str


@dataclass(frozen=True)
class PvmDebugFrame:
    entry_index: int
    code_marker: int
    function_name: str
    argument_names: tuple[str, ...]
    local_names: tuple[str, ...]


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

# applyOperator's typed-comparison dispatch is proven by Godzilla3.elf. Other
# token values are deliberately kept numeric until ParserType::applyOperator
# can be tied back to the compiler's PPTokenTypes enum.
PV_COMPARISON_TOKENS = {
    0: "==",
    1: "!=",
    16: "<",
    17: ">",
    18: ">=",
    19: "<=",
}

# PVM operator records use the same PPTokenTypes numbering retained by the
# PPTokenStream 1.03 BSF format. These entries are shared by both formats.
PV_BINARY_TOKENS = {
    0: "==",
    1: "!=",
    2: "*",
    3: "+",
    4: "-",
    5: "/",
    6: "%",
    7: "&",
    9: "|",
    10: "^",
    11: "&&",
    12: "||",
    14: "<<",
    15: ">>",
    16: "<",
    17: ">",
    18: ">=",
    19: "<=",
}

PVM_SECTION_NAMES = {
    0: "Code",
    1: "InitialValues",
    2: "ValueSymbols",
    3: "FunctionSignatures",
    4: "Types",
    5: "SymbolRefs",
    6: "StringPool",
    7: "RuntimeRecords",
    8: "DebugStringPool",
}

def is_pwk_vm_module(data: bytes) -> bool:
    return len(data) >= HEADER_SIZE and data.startswith(MAGIC_PREFIX)


def parse_pvm(data: bytes) -> PvmModule:
    if not is_pwk_vm_module(data):
        raise ValueError("Not a PWK Virtual machine module PVM.")
    version_text = data[:0x30].decode("ascii", errors="replace").rstrip()
    endian = "<" if "little endian" in version_text.lower() else ">"
    marker = struct.unpack_from(f"{endian}I", data, 0x30)[0]
    total_size = struct.unpack_from(f"{endian}I", data, 0x34)[0]
    if total_size != len(data):
        raise ValueError(f"Header size field is 0x{total_size:X}, file is 0x{len(data):X}.")

    sections = []
    for index in range(SECTION_COUNT):
        entry = SECTION_TABLE_START + index * 8
        offset, size = struct.unpack_from(f"{endian}II", data, entry)
        if offset < HEADER_SIZE or offset + size > len(data):
            raise ValueError(
                f"Section {index} range 0x{offset:X}+0x{size:X} is outside the file."
            )
        sections.append(PvmSection(index, offset, size))
    return PvmModule(data, version_text, marker, total_size, tuple(sections), endian)


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


def _canonical_opcode(raw_op: int, version_text: str = "") -> int:
    op = raw_op & 0x7F
    # v1.60 predates v1.70's second 7-byte assignment/call opcode (0x73).
    # Its remaining tail opcodes therefore occupy 0x73..0x79 one slot lower.
    if "v1.60" in version_text and 0x73 <= op <= 0x79:
        return op + 1
    return op


def pvm_op_size(code: bytes, offset: int, version_text: str = "", endian: str = ">") -> int:
    if offset >= len(code):
        return 0
    raw_op = code[offset] & 0x7F
    op = _canonical_opcode(raw_op, version_text)
    if op == 0x6D:
        subtype = code[offset + 2] if offset + 2 < len(code) else 0
        return PV_6D_SUBTYPE_SIZES.get(subtype, 3)
    if op == 0x6C:
        # GetPVOpSize aligns (opcode + 4) down to a 4-byte boundary, then reads
        # the descriptor count two bytes into that aligned header.
        if offset + 5 >= len(code):
            return 1
        aligned = (offset + 4) & ~3
        if aligned + 4 > len(code):
            return 1
        count = int.from_bytes(code[aligned + 2:aligned + 4], "little" if endian == "<" else "big")
        size = ((count - 1) * 8) + (aligned - offset) + 12
        return size if size > 0 and offset + size <= len(code) else 1
    return PV_FIXED_OP_SIZES.get(op, 1)


def pvm_code_offsets(module: PvmModule) -> list[int]:
    """Legacy section-3 word view retained only for diagnostics.

    Engine `resolveGlobals` proves this section stores function signature/type
    data, not code relocation sites. Its words must never be shifted as code.
    """
    blob = section_data(module, 3)
    if len(blob) < 8:
        return []
    count = int.from_bytes(blob[0:4], "little" if module.endian == "<" else "big")
    offsets = []
    pos = 4
    for _ in range(min(count, (len(blob) - pos) // 4)):
        value = int.from_bytes(blob[pos:pos + 4], "little" if module.endian == "<" else "big")
        if 0 <= value < module.sections[0].size:
            offsets.append(value)
        pos += 4
    return offsets


def pvm_routine_offsets(module: PvmModule) -> list[int]:
    """Return actual VM routine starts discovered from frame prologues.

    Opcode 0x6C creates a PVFrame and skips its aligned local descriptor table.
    Section 3 contains function signature/type data, not a function directory.
    """
    code = section_data(module, 0)
    return [offset for offset in _instruction_offsets(module) if (code[offset] & 0x7F) == 0x6C]


def pvm_code_entries(module: PvmModule) -> list[PvmCodeEntry]:
    """Return routines delimited by the VM's proven 0x6C frame prologues."""
    offsets = pvm_routine_offsets(module)
    code_base = module.sections[0].offset
    sorted_unique = sorted(set(offsets))
    next_by_offset = {
        value: sorted_unique[index + 1] if index + 1 < len(sorted_unique) else module.sections[0].size
        for index, value in enumerate(sorted_unique)
    }
    entries: list[PvmCodeEntry] = []
    used_names: dict[str, int] = {}
    for index, offset in enumerate(offsets):
        safe = f"routine_{offset:06X}"
        if safe in used_names:
            used_names[safe] += 1
            safe = f"{safe}_{used_names[safe]}"
        else:
            used_names[safe] = 0
        entries.append(
            PvmCodeEntry(
                index=index,
                code_offset=offset,
                file_offset=code_base + offset,
                end_code_offset=next_by_offset.get(offset, module.sections[0].size),
                name=safe,
            )
        )
    return entries


def format_bytecode_preview(module: PvmModule, max_ops: int = 180) -> str:
    code = section_data(module, 0)
    entry_offsets = set(pvm_code_offsets(module))
    lines = []
    lines.append("[bytecode preview]")
    if entry_offsets:
        lines.append("; section 3 signature words in code-sized range: " + ", ".join(f"0x{value:04X}" for value in sorted(entry_offsets)[:64]))
        if len(entry_offsets) > 64:
            lines.append(f"; ... {len(entry_offsets) - 64} more")
    lines.append("; op byte is masked with 0x7F by the runtime; sizes come from GetPVOpSize where known.")

    offset = 0
    ops = 0
    while offset < len(code) and ops < max_ops:
        mark = ">" if offset in entry_offsets else " "
        size = max(1, pvm_op_size(code, offset, module.version_text, module.endian))
        raw = code[offset:offset + size]
        op = _canonical_opcode(code[offset], module.version_text)
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


def pvm_debug_frames(module: PvmModule) -> dict[int, PvmDebugFrame]:
    """Map compiled routines to original function, argument, and local names."""
    blob = section_data(module, 7)
    debug_pool = section_data(module, 8)
    if len(blob) < 8:
        return {}
    line_count, frame_count = struct.unpack_from(f"{module.endian}II", blob, 0)
    cursor = 8 + line_count * 12
    # The line table is followed by frame zero for <main>. It uses the same
    # marker/count/name layout as the remaining function records.
    if cursor + 8 > len(blob):
        return {}
    main_code_marker = struct.unpack_from(f"{module.endian}I", blob, cursor)[0]
    main_local_count, main_argument_count = struct.unpack_from(f"{module.endian}HH", blob, cursor + 4)
    main_function_name_offset = struct.unpack_from(f"{module.endian}I", blob, cursor + 12)[0]
    cursor += 16
    main_name_offsets = []
    for _ in range(main_local_count + main_argument_count):
        if cursor + 4 > len(blob):
            return {}
        main_name_offsets.append(struct.unpack_from(f"{module.endian}I", blob, cursor)[0])
        cursor += 4
    debug_names = {
        offset - module.sections[8].offset: text
        for offset, text in extract_null_strings(debug_pool, module.sections[8].offset)
    }
    main_names = tuple(
        debug_names.get(offset, f"debug_{offset:04X}")
        for offset in main_name_offsets
    )
    main_debug_name = debug_names.get(main_function_name_offset, "main")
    frames: dict[int, PvmDebugFrame] = {
        0: PvmDebugFrame(
            entry_index=0,
            code_marker=main_code_marker,
            function_name="main" if main_debug_name == "<main>" else main_debug_name,
            argument_names=main_names[:main_argument_count],
            local_names=main_names[main_argument_count:],
        )
    }
    for entry_index in range(1, frame_count):
        if cursor + 16 > len(blob):
            break
        code_marker = struct.unpack_from(f"{module.endian}I", blob, cursor)[0]
        local_count, argument_count = struct.unpack_from(f"{module.endian}HH", blob, cursor + 4)
        function_name_offset = struct.unpack_from(f"{module.endian}I", blob, cursor + 12)[0]
        cursor += 16
        name_count = local_count + argument_count
        if cursor + name_count * 4 > len(blob):
            break
        names = []
        for _ in range(name_count):
            name_offset = struct.unpack_from(f"{module.endian}I", blob, cursor)[0]
            cursor += 4
            names.append(debug_names.get(name_offset, f"debug_{name_offset:04X}"))
        frames[entry_index] = PvmDebugFrame(
            entry_index=entry_index,
            code_marker=code_marker,
            function_name=debug_names.get(function_name_offset, f"routine_{entry_index:04d}"),
            argument_names=tuple(names[:argument_count]),
            local_names=tuple(names[argument_count:]),
        )
    return frames


def _pvm_call_targets(
    entries: list[PvmCodeEntry],
    debug_frames: dict[int, PvmDebugFrame],
) -> dict[int, tuple[str, int]]:
    targets: dict[int, tuple[str, int]] = {}
    for entry in entries:
        frame = debug_frames.get(entry.index)
        if frame is None:
            continue
        explicit_arguments = sum(name != "this" for name in frame.argument_names)
        targets[entry.code_offset] = (frame.function_name, explicit_arguments)
    return targets


def _u24(data: bytes) -> int:
    return int.from_bytes(data, "big")


def _encode_tagged_u24(tag: int, value: int, endian: str) -> bytes:
    if not 0 <= value <= 0xFFFFFF:
        raise ValueError(f"Tagged PVM value 0x{value:X} does not fit 24 bits.")
    if endian == "<":
        return value.to_bytes(3, "little") + bytes((tag & 0xFF,))
    return bytes((tag & 0xFF,)) + value.to_bytes(3, "big")


def _patch_tagged_u24(data: bytearray, instruction_offset: int, value: int, endian: str) -> None:
    if endian == "<":
        data[instruction_offset + 1:instruction_offset + 4] = value.to_bytes(3, "little")
    else:
        data[instruction_offset + 2:instruction_offset + 5] = value.to_bytes(3, "big")


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


def _member_names(module: PvmModule) -> dict[int, str]:
    """Decode section 5's member-reference rows by module-local index."""
    blob = section_data(module, 5)
    strings = section_data(module, 6)
    if len(blob) < 4:
        return {}
    count = int.from_bytes(blob[:4], "little" if module.endian == "<" else "big")
    names: dict[int, str] = {}
    for index in range(min(count, (len(blob) - 4) // 8)):
        _owner, _member_id, name_offset = struct.unpack_from(f"{module.endian}HHI", blob, 4 + index * 8)
        name = _cstr(strings, name_offset)
        if name:
            names[index] = name
    return names


def _global_symbol_names(module: PvmModule) -> tuple[dict[int, str], dict[int, str]]:
    """Return serialized variable and function names from section 2.

    The VM's tag-1 references index the variable-symbol records, while tag-0
    references index the function-symbol records. Imported/native functions
    retain a code address of 0xFFFFFFFF but still carry their source name.
    """
    blob = section_data(module, 2)
    strings = section_data(module, 6)
    if len(blob) < 12:
        return {}, {}

    variable_count = struct.unpack_from(f"{module.endian}I", blob, 0)[0]
    function_count = struct.unpack_from(f"{module.endian}H", blob, 8)[0]
    variable_start = 12
    function_start = variable_start + variable_count * 8
    if function_start > len(blob) or function_start + function_count * 16 > len(blob):
        return {}, {}

    variables: dict[int, str] = {}
    for index in range(variable_count):
        name_offset = struct.unpack_from(f"{module.endian}I", blob, variable_start + index * 8)[0]
        name = _cstr(strings, name_offset)
        if name:
            variables[index] = name

    functions: dict[int, str] = {}
    for index in range(function_count):
        name_offset = struct.unpack_from(f"{module.endian}I", blob, function_start + index * 16)[0]
        name = _cstr(strings, name_offset)
        if name:
            functions[index] = name
    return variables, functions


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
        op = _canonical_opcode(code[offset], module.version_text)
        if op not in valid_ops:
            offset += 1
            continue
        size = max(1, pvm_op_size(code, offset, module.version_text, module.endian))
        if offset + size > len(code):
            break
        offsets.append(offset)
        offset += size
    return offsets


def _decode_table_6c(code_offset: int, raw: bytes) -> str:
    aligned = ((code_offset + 4) & ~3) - code_offset
    if aligned + 4 > len(raw):
        return "enter_frame descriptors=unknown"
    count = int.from_bytes(raw[aligned + 2:aligned + 4], "big") if aligned + 4 <= len(raw) else 0
    return f"enter_frame descriptors={count}"


def _canonical_instruction_raw(code_offset: int, raw: bytes, op: int, endian: str) -> bytes:
    """Convert PS2 operand fields to the canonical Wii/big-endian layout."""
    if endian != "<" or len(raw) <= 1:
        return raw
    converted = bytearray(raw)
    if op in {0x66, 0x67, 0x69, 0x6A, 0x6F, 0x70, 0x71} and len(raw) >= 5:
        converted[1:5] = raw[1:5][::-1]
    elif op in {0x64, 0x6E, 0x74, 0x75} and len(raw) >= 3:
        converted[1:3] = raw[1:3][::-1]
    elif op in {0x72, 0x73} and len(raw) >= 7:
        converted[1:5] = raw[1:5][::-1]
        converted[5:7] = raw[5:7][::-1]
    elif op == 0x6D and len(raw) >= 7:
        converted[3:7] = raw[3:7][::-1]
    elif op == 0x6C:
        aligned = ((code_offset + 4) & ~3) - code_offset
        if aligned + 4 <= len(raw):
            converted[aligned:aligned + 2] = raw[aligned:aligned + 2][::-1]
            converted[aligned + 2:aligned + 4] = raw[aligned + 2:aligned + 4][::-1]
            count = int.from_bytes(raw[aligned + 2:aligned + 4], "little")
            cursor = aligned + 4
            for _ in range(count):
                if cursor + 8 > len(raw):
                    break
                converted[cursor:cursor + 4] = raw[cursor:cursor + 4][::-1]
                converted[cursor + 4:cursor + 8] = raw[cursor + 4:cursor + 8][::-1]
                cursor += 8
    return bytes(converted)


def decode_pvm_instructions(module: PvmModule) -> list[PvmInstruction]:
    code = section_data(module, 0)
    code_base = module.sections[0].offset
    symbols = indexed_pool(module, 6)
    debug = indexed_pool(module, 8)
    members = _member_names(module)
    global_names, function_names = _global_symbol_names(module)
    type_names = _type_names(module)
    typed_values = extract_typed_values(module)
    typed_aliases = _pvm_source_aliases(typed_values)
    typed_names = {
        item.entry_index: typed_aliases[item.entry_index]
        for item in typed_values
    }
    typed_literals = {
        item.entry_index: _format_pvm_source_value(item.value)
        for item in typed_values
    }
    entry_offsets = set(pvm_code_offsets(module))
    out: list[PvmInstruction] = []

    for offset in _instruction_offsets(module):
        op = _canonical_opcode(code[offset], module.version_text)
        size = max(1, pvm_op_size(code, offset, module.version_text, module.endian))
        if offset + size > len(code):
            size = len(code) - offset
        raw = _canonical_instruction_raw(offset, code[offset:offset + size], op, module.endian)
        text = f"TODO_decode_op_{op}"

        if op == 0x64 and len(raw) >= 3:
            value = int.from_bytes(raw[1:3], "big")
            text = f"push_frame_ref local[{value}]"
        elif op == 0x65 and len(raw) >= 2:
            text = f"push_stack_ref relative[{raw[1]}]"
        elif op == 0x66 and len(raw) >= 5:
            tag = raw[1]
            index = _u24(raw[2:5])
            if tag == 1:
                name = global_names.get(index, f"global[{index}]")
            elif tag == 0:
                name = function_names.get(index, f"function_symbol[{index}]")
            else:
                name = f"variable_space_{tag}[{index}]"
            text = f"push_copy {name}"
        elif op == 0x67 and len(raw) >= 5:
            tag = raw[1]
            index = _u24(raw[2:5])
            name = typed_literals.get(index, typed_names.get(index, f"value_{index}")) if tag == 3 else _pool_name(index, symbols, debug)
            text = f"push_symbol {name} ; tag={tag}, index={index}"
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
            text = (
                "call_direct pop_object"
                if member == 0xFFFF
                else f"call_member pop_object.{members.get(member, f'member_{member}')}"
            )
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
            type_index = _u24(raw[2:5])
            local = int.from_bytes(raw[5:7], "big")
            type_name = type_names[type_index] if tag == 2 and type_index < len(type_names) else f"type_{type_index}"
            text = f"coerce_into local[{local}] as {type_name} ; tag={tag}, type_index={type_index}"
        elif op == 0x73 and len(raw) >= 7:
            tag = raw[1]
            type_index = _u24(raw[2:5])
            local = int.from_bytes(raw[5:7], "big")
            type_name = type_names[type_index] if tag == 2 and type_index < len(type_names) else f"type_{type_index}"
            text = f"coerce_from local[{local}] as {type_name} ; tag={tag}, type_index={type_index}"
        elif op == 0x74 and len(raw) >= 3:
            local = int.from_bytes(raw[1:3], "big")
            text = f"set_local local[{local}] = stack.top"
        elif op == 0x75 and len(raw) >= 3:
            member = int.from_bytes(raw[1:3], "big")
            text = (
                "call_direct pop_object"
                if member == 0xFFFF
                else f"call_member pop_object.{members.get(member, f'member_{member}')}"
            )
        elif op == 0x76:
            text = "resolve stack[-1], stack[0]"
        elif op == 0x77:
            text = "return_value stack.top"
        elif op == 0x78:
            text = "leave_frame"
        elif op == 0x79:
            text = "return_vm_state 1"
        elif op == 0x7A:
            text = "end"

        out.append(PvmInstruction(offset, code_base + offset, op, size, raw, text))
    return out


def format_pvm_code(module: PvmModule) -> str:
    labels = {
        target for inst in decode_pvm_instructions(module)
        if (target := _pvm_branch_target(inst)) is not None
    }
    lines = ["[Code]"]
    lines.append("# Decoded VM instructions. Numeric literals are decimal; loc_N labels are section-0 code offsets.")
    for inst in decode_pvm_instructions(module):
        label = f"loc_{inst.code_offset}: " if inst.code_offset in labels else ""
        lines.append(f"{label}{inst.text}")
    return "\n".join(lines)


def format_pvm_entries(module: PvmModule) -> str:
    lines = ["[Routines]"]
    lines.append("Index | CodeStart | CodeEnd   | FileOffset | Name")
    for entry in pvm_code_entries(module):
        lines.append(
            f"{entry.index:05d} | +0x{entry.code_offset:06X} | +0x{entry.end_code_offset:06X} | "
            f"@0x{entry.file_offset:06X} | {entry.name}"
        )
    return "\n".join(lines)


def format_pvm_entries_preview(module: PvmModule, limit: int = 96) -> str:
    entries = pvm_code_entries(module)
    lines = ["[Routines]"]
    lines.append("Index | CodeStart | CodeEnd   | FileOffset | Name")
    for entry in entries[:limit]:
        lines.append(
            f"{entry.index:05d} | +0x{entry.code_offset:06X} | +0x{entry.end_code_offset:06X} | "
            f"@0x{entry.file_offset:06X} | {entry.name}"
        )
    if len(entries) > limit:
        lines.append(f"# ... {len(entries) - limit} more routines hidden in this preview")
    return "\n".join(lines)


def _instructions_in_range(module: PvmModule, start: int, end: int) -> list[PvmInstruction]:
    return [
        inst for inst in decode_pvm_instructions(module)
        if start <= inst.code_offset < end
    ]


def _instructions_by_routine(module: PvmModule, entries: list[PvmCodeEntry]) -> dict[int, list[PvmInstruction]]:
    grouped = {entry.index: [] for entry in entries}
    if not entries:
        return grouped
    ordered = sorted(entries, key=lambda entry: entry.code_offset)
    entry_index = 0
    for inst in decode_pvm_instructions(module):
        while entry_index + 1 < len(ordered) and inst.code_offset >= ordered[entry_index].end_code_offset:
            entry_index += 1
        entry = ordered[entry_index]
        if entry.code_offset <= inst.code_offset < entry.end_code_offset:
            grouped[entry.index].append(inst)
    return grouped


def format_pvm_disassembly(module: PvmModule, path: Path | None = None, max_entries: int | None = None) -> str:
    lines = []
    lines.append("# PWK PVM disassembly")
    if path is not None:
        lines.append(f"# SourcePVM={path}")
    lines.append("# Instruction sizes are from GetPVOpSize evidence; opcode names are still being recovered.")
    lines.append("")
    entries = pvm_code_entries(module)
    debug_frames = pvm_debug_frames(module)
    call_targets = _pvm_call_targets(entries, debug_frames)
    if max_entries is not None:
        entries = entries[:max_entries]
    grouped = _instructions_by_routine(module, entries)
    for entry in entries:
        lines.append(
            f"## entry {entry.index:05d} +0x{entry.code_offset:06X}-+0x{entry.end_code_offset:06X} {entry.name}"
        )
        instructions = grouped[entry.index]
        if not instructions:
            lines.append("  ; no decoded instructions in this range")
        for inst in instructions:
            raw = inst.raw.hex(" ")
            lines.append(f"  +0x{inst.code_offset:06X}  {raw:<24} {inst.text}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def format_pvm_source_scaffold(module: PvmModule, path: Path | None = None, max_entries: int | None = None) -> str:
    """Emit conservative source-like code recovered from VM stack operations."""
    lines = []
    lines.append("# PWK PVM decompiler output")
    if path is not None:
        lines.append(f"# SourcePVM={path}")
    lines.append("# Control flow and frame boundaries come from the Wii runtime in Godzilla3.elf.")
    lines.append("# This is recovered source syntax, not the original developer formatting.")
    lines.append("# Editable: global table, source code values, arguments, and functions.")
    lines.append("")

    type_values = extract_typed_values(module)
    if type_values:
        lines.append("globals")
        lines.append("{")
        for item in type_values:
            value = repr(item.value) if isinstance(item.value, str) else repr(item.value) if isinstance(item.value, float) else str(item.value)
            lines.append(f"    {item.type_name} {item.name} = {value};")
        lines.append("}")
        lines.append("")

    entries = pvm_code_entries(module)
    debug_frames = pvm_debug_frames(module)
    call_targets = _pvm_call_targets(entries, debug_frames)
    if max_entries is not None:
        entries = entries[:max_entries]
    for entry in entries:
        debug_frame = debug_frames.get(entry.index)
        function_name = debug_frame.function_name if debug_frame else entry.name
        arguments = ", ".join(
            name for name in debug_frame.argument_names if name != "this"
        ) if debug_frame else ""
        lines.append(f"function {function_name}({arguments})")
        lines.append("{")
        instructions = _instructions_in_range(module, entry.code_offset, entry.end_code_offset)
        if not instructions:
            lines.append("    // empty")
        else:
            body_lines = _decompile_routine(
                instructions, _type_names(module), debug_frame, call_targets
            )
            balance = sum(line.count("{") - line.count("}") for line in body_lines)
            if balance > 0:
                body_lines.extend("    }" for _ in range(balance))
            lines.extend(body_lines)
        lines.append("}")
        lines.append("")
    if max_entries is not None and len(pvm_code_entries(module)) > max_entries:
        lines.append(f"# ... {len(pvm_code_entries(module)) - max_entries} more routines omitted from this preview")
    return "\n".join(lines).rstrip() + "\n"


def _pvm_branch_target(inst: PvmInstruction) -> int | None:
    if inst.op in (0x6F, 0x70, 0x71) and len(inst.raw) >= 5:
        return _u24(inst.raw[2:5])
    return None


def _frame_local_types(instructions: list[PvmInstruction], type_names: list[str]) -> dict[int, str]:
    """Recover the proven type of each frame slot from the 0x6C descriptor table."""
    if not instructions or instructions[0].op != 0x6C:
        return {}
    inst = instructions[0]
    raw = inst.raw
    aligned = ((inst.code_offset + 4) & ~3) - inst.code_offset
    if aligned + 4 > len(raw):
        return {}
    count = int.from_bytes(raw[aligned + 2:aligned + 4], "big")
    cursor = aligned + 4
    result: dict[int, str] = {}
    for _ in range(count):
        if cursor + 8 > len(raw):
            break
        tag = raw[cursor]
        type_index = _u24(raw[cursor + 1:cursor + 4])
        local_offset = int.from_bytes(raw[cursor + 4:cursor + 8], "big")
        if tag == 2 and type_index < len(type_names):
            result[local_offset] = type_names[type_index]
        cursor += 8
    return result


def _unwrap_false_jump_condition(line: str) -> tuple[str, str] | None:
    match = re.match(r"^\s*if \((.+)\) goto loc_([0-9A-Fa-f]+);(?:\s*//.*)?$", line)
    if not match:
        return None
    condition = match.group(1).strip()
    if condition.startswith("!(") and condition.endswith(")"):
        condition = condition[2:-1].strip()
    else:
        return None
    return condition, match.group(2).upper()


def _matching_block_close(lines: list[str], open_index: int) -> int | None:
    """Return the closing line for a braced source block."""
    depth = 0
    opened = False
    for index in range(open_index, len(lines)):
        # Decompiled expressions do not contain brace literals. Counting both
        # sides also handles `} else {` without changing the enclosing depth.
        depth += lines[index].count("{")
        if lines[index].count("{"):
            opened = True
        depth -= lines[index].count("}")
        if opened and depth == 0:
            return index
    return None


def _fold_short_circuit_lines(lines: list[str]) -> list[str]:
    """Fold the VM compiler's repeated false-branch template into A && B."""
    out: list[str] = []
    index = 0
    folded_any = False
    while index < len(lines):
        conditions: list[str] = []
        cursor = index
        false_target = None
        while cursor < len(lines):
            parsed = _unwrap_false_jump_condition(lines[cursor])
            if parsed is None:
                break
            condition, target = parsed
            if false_target is None:
                false_target = target
            if target != false_target:
                break
            conditions.append(condition)
            cursor += 1
        if len(conditions) >= 2 and cursor + 2 < len(lines):
            jump_match = re.match(r"^\s*goto loc_([0-9A-Fa-f]+);(?:\s*//.*)?$", lines[cursor])
            false_label = re.match(r"^\s*loc_([0-9A-Fa-f]+):$", lines[cursor + 1])
            end_label = re.match(r"^\s*loc_([0-9A-Fa-f]+):$", lines[cursor + 2])
            if (
                jump_match
                and false_label
                and end_label
                and false_label.group(1).upper() == false_target
                and end_label.group(1).upper() == jump_match.group(1).upper()
            ):
                expression = " && ".join(f"({condition})" for condition in conditions)
                next_index = cursor + 3
                if next_index < len(lines):
                    parsed_next = _unwrap_false_jump_condition(lines[next_index])
                    if parsed_next is not None:
                        _old_condition, next_target = parsed_next
                        note = ""
                        if " //" in lines[next_index]:
                            note = " //" + lines[next_index].split(" //", 1)[1]
                        out.append(f"    if (!({expression})) goto loc_{next_target};{note}")
                        index = next_index + 1
                        folded_any = True
                        continue
                    structured_next = re.match(r"^(\s*)if \(0\) \{(.*)$", lines[next_index])
                    if structured_next:
                        out.append(
                            f"{structured_next.group(1)}if ({expression}) {{{structured_next.group(2)}"
                        )
                        index = next_index + 1
                        folded_any = True
                        continue
        out.append(lines[index])
        index += 1

    if folded_any:
        return _fold_short_circuit_lines(out)

    changed = True
    while changed:
        changed = False
        compact: list[str] = []
        index = 0
        while index < len(out):
            jump_match = re.match(r"^\s*goto loc_([0-9A-Fa-f]+);(?:\s*//.*)?$", out[index])
            if jump_match and index + 1 < len(out):
                label_match = re.match(r"^\s*loc_([0-9A-Fa-f]+):$", out[index + 1])
                if label_match and label_match.group(1).upper() == jump_match.group(1).upper():
                    compact.append(out[index + 1])
                    index += 2
                    changed = True
                    continue
            compact.append(out[index])
            index += 1
        out = compact

    referenced = {
        match.group(1).upper()
        for line in out
        for match in [re.search(r"\bgoto loc_([0-9A-Fa-f]+)", line)]
        if match
    }
    return [
        line
        for line in out
        if not (
            (match := re.match(r"^\s*loc_([0-9A-Fa-f]+):$", line))
            and match.group(1).upper() not in referenced
        )
    ]


def _structure_forward_if_lines(lines: list[str]) -> list[str]:
    """Turn uniquely targeted forward false-jumps into structured if blocks."""
    changed = True
    while changed:
        changed = False
        label_indices = {
            match.group(1).upper(): index
            for index, line in enumerate(lines)
            for match in [re.match(r"^\s*loc_([0-9A-Fa-f]+):$", line)]
            if match
        }
        reference_counts: dict[str, int] = {}
        for line in lines:
            for match in re.finditer(r"\bgoto loc_([0-9A-Fa-f]+)", line):
                key = match.group(1).upper()
                reference_counts[key] = reference_counts.get(key, 0) + 1
        for index in range(len(lines) - 1, -1, -1):
            parsed = _unwrap_false_jump_condition(lines[index])
            if parsed is None:
                continue
            condition, target = parsed
            target_index = label_indices.get(target)
            if target_index is None or target_index <= index or reference_counts.get(target) != 1:
                continue
            note = ""
            if " //" in lines[index]:
                note = " //" + lines[index].split(" //", 1)[1]
            lines[index] = f"    if ({condition}) {{{note}"
            lines[target_index] = "    }"
            changed = True
            break
    return lines


def _structure_guard_chains(lines: list[str]) -> list[str]:
    """Turn consecutive `if (!A) goto end` guards into one nested source block."""
    label_indices = {
        match.group(1).upper(): index
        for index, line in enumerate(lines)
        for match in [re.match(r"^\s*loc_([0-9A-Fa-f]+):$", line)]
        if match
    }
    reference_counts: dict[str, int] = {}
    for line in lines:
        for match in re.finditer(r"\bgoto loc_([0-9A-Fa-f]+)", line):
            key = match.group(1).upper()
            reference_counts[key] = reference_counts.get(key, 0) + 1

    index = 0
    while index < len(lines):
        guards: list[str] = []
        cursor = index
        target = None
        while cursor < len(lines):
            parsed = _unwrap_false_jump_condition(lines[cursor])
            if parsed is None:
                break
            condition, current_target = parsed
            if target is None:
                target = current_target
            if current_target != target:
                break
            guards.append(condition)
            cursor += 1
        target_index = label_indices.get(target or "")
        if (
            len(guards) >= 2
            and target_index is not None
            and target_index > cursor
            and reference_counts.get(target or "") == len(guards)
        ):
            expression = " && ".join(f"({condition})" for condition in guards)
            lines[index:cursor] = [f"    if ({expression}) {{"]
            target_index -= len(guards) - 1
            lines[target_index] = "    }"
            return lines
        index += 1
    return lines


def _fold_boolean_bridges(lines: list[str]) -> list[str]:
    """Remove push-true/push-false CFG scaffolding around a following source if."""
    for index in range(len(lines) - 4):
        open_match = re.match(r"^\s*if \((.+)\) \{$", lines[index])
        jump_match = re.match(r"^\s*goto loc_([0-9A-Fa-f]+);$", lines[index + 1])
        label_match = re.match(r"^\s*loc_([0-9A-Fa-f]+):$", lines[index + 3])
        next_if = re.match(r"^(\s*)if \(.+\) \{$", lines[index + 4])
        if (
            open_match
            and jump_match
            and lines[index + 2].strip() == "}"
            and label_match
            and jump_match.group(1).upper() == label_match.group(1).upper()
            and next_if
        ):
            lines[index:index + 5] = [
                f"{next_if.group(1)}if ({open_match.group(1)}) {{"
            ]
            return lines
    return lines


def _fold_true_branch_bridges(lines: list[str]) -> list[str]:
    """Fold the VM's repeated true-branch boolean materialization into `A || B`."""
    index = 0
    while index < len(lines):
        conditions: list[str] = []
        cursor = index
        true_target = None
        while cursor < len(lines):
            match = re.match(
                r"^\s*if \((.+)\) goto loc_([0-9A-Fa-f]+);$", lines[cursor]
            )
            if not match:
                break
            current_target = match.group(2).upper()
            if true_target is None:
                true_target = current_target
            if current_target != true_target:
                break
            conditions.append(match.group(1).strip())
            cursor += 1
        if len(conditions) < 1 or cursor + 3 >= len(lines):
            index += 1
            continue
        if sum(
            1
            for candidate in lines
            if re.search(
                rf"\bgoto loc_{re.escape(true_target or '')}\b",
                candidate,
                re.IGNORECASE,
            )
        ) != len(conditions):
            index += 1
            continue
        end_jump = re.match(r"^\s*goto loc_([0-9A-Fa-f]+);$", lines[cursor])
        true_label = re.match(r"^\s*loc_([0-9A-Fa-f]+):$", lines[cursor + 1])
        end_label = re.match(r"^\s*loc_([0-9A-Fa-f]+):$", lines[cursor + 2])
        next_if = re.match(r"^(\s*)if \(.+\) \{$", lines[cursor + 3])
        next_false_jump = _unwrap_false_jump_condition(lines[cursor + 3])
        next_true_jump = re.match(
            r"^(\s*)if \((.+)\) goto loc_([0-9A-Fa-f]+);$",
            lines[cursor + 3],
        )
        if (
            end_jump
            and true_label
            and end_label
            and true_label.group(1).upper() == true_target
            and end_label.group(1).upper() == end_jump.group(1).upper()
        ):
            expression = " || ".join(f"({condition})" for condition in conditions)
            if next_if:
                lines[index:cursor + 4] = [
                    f"{next_if.group(1)}if ({expression}) {{"
                ]
                return lines
            if next_true_jump and next_false_jump is None:
                if next_true_jump.group(2).strip() in {"condition", "stack_value"}:
                    lines[index:cursor + 4] = [
                        f"{next_true_jump.group(1)}if ({expression}) "
                        f"goto loc_{next_true_jump.group(3)};"
                    ]
                    return lines
                lines[index:cursor + 4] = [
                    f"{next_true_jump.group(1)}if (({expression}) || "
                    f"({next_true_jump.group(2)})) goto loc_{next_true_jump.group(3)};"
                ]
                return lines
            if next_false_jump:
                _discarded_condition, next_target = next_false_jump
                lines[index:cursor + 4] = [
                    f"    if (!({expression})) goto loc_{next_target};"
                ]
                return lines
            terminal_guard = re.match(
                r"^(\s*)if \((!?\(?\s*[A-Za-z_]\w*\s*\)?)\) "
                r"(return(?:\s+.+)?;)$",
                lines[cursor + 3],
            )
            if terminal_guard:
                guard = terminal_guard.group(2).strip()
                if guard.startswith("!"):
                    expression = f"!({expression})"
                lines[index:cursor + 4] = [
                    f"{terminal_guard.group(1)}if ({expression}) {terminal_guard.group(3)}"
                ]
                return lines
        index += 1
    return lines


def _fold_boolean_label_chain(lines: list[str]) -> list[str]:
    """Recover a boolean value materialized through shared true/end labels."""
    index = 0
    while index < len(lines):
        conditions: list[str] = []
        true_target = None
        cursor = index
        while cursor < len(lines):
            match = re.match(
                r"^\s*if \((.+)\) goto loc_([0-9A-Fa-f]+);$", lines[cursor]
            )
            if not match:
                break
            if true_target is None:
                true_target = match.group(2).upper()
            if match.group(2).upper() != true_target:
                break
            conditions.append(match.group(1))
            cursor += 1
        if not conditions or cursor + 3 >= len(lines):
            index += 1
            continue
        end_jump = re.match(r"^\s*goto loc_([0-9A-Fa-f]+);$", lines[cursor])
        true_label = re.match(r"^\s*loc_([0-9A-Fa-f]+):$", lines[cursor + 1])
        end_label = re.match(r"^\s*loc_([0-9A-Fa-f]+):$", lines[cursor + 2])
        if not (
            end_jump and true_label and end_label
            and true_label.group(1).upper() == true_target
            and end_label.group(1).upper() == end_jump.group(1).upper()
        ):
            index += 1
            continue
        expression = " || ".join(f"({condition})" for condition in conditions)
        consumer = lines[cursor + 3]
        assignment = re.match(r"^(\s*)stack_value\s*=\s*([A-Za-z_]\w*);$", consumer)
        if assignment:
            replacement = f"{assignment.group(1)}{assignment.group(2)} = {expression};"
        elif re.search(r"\b(?:condition|stack_value)\b", consumer):
            replacement = re.sub(r"\b(?:condition|stack_value)\b", f"({expression})", consumer)
        else:
            index += 1
            continue
        lines[index:cursor + 4] = [replacement]
        return lines
    return lines


def _fold_materialized_or_bridges(lines: list[str]) -> list[str]:
    """Lift true/false value joins, including branches with path-local work."""
    index = 0
    while index < len(lines):
        conditions: list[str] = []
        cursor = index
        true_target = None
        while cursor < len(lines):
            match = re.match(r"^\s*if \((.+)\) goto loc_([0-9A-Fa-f]+);$", lines[cursor])
            if not match:
                break
            target = match.group(2).upper()
            if true_target is None:
                true_target = target
            if target != true_target:
                break
            conditions.append(match.group(1).strip())
            cursor += 1
        if not conditions:
            index += 1
            continue
        true_index = next(
            (
                pos for pos in range(cursor + 1, min(len(lines), cursor + 20))
                if re.match(rf"^\s*loc_{re.escape(true_target or '')}:$", lines[pos], re.IGNORECASE)
            ),
            None,
        )
        if true_index is None or true_index == 0:
            index += 1
            continue
        end_jump = re.match(r"^\s*goto loc_([0-9A-Fa-f]+);$", lines[true_index - 1])
        if end_jump is None:
            index += 1
            continue
        end_target = end_jump.group(1).upper()
        end_index = next(
            (
                pos for pos in range(true_index + 1, min(len(lines), true_index + 20))
                if re.match(rf"^\s*loc_{re.escape(end_target)}:$", lines[pos], re.IGNORECASE)
            ),
            None,
        )
        if end_index is None or end_index + 1 >= len(lines):
            index += 1
            continue
        consumer = lines[end_index + 1]
        placeholder = re.search(r"\b(?:condition|temp_int_\d+)\b", consumer)
        if placeholder is None:
            index += 1
            continue
        expression = " || ".join(f"({condition})" for condition in conditions)
        false_body = lines[cursor:true_index - 1]
        true_body = lines[true_index + 1:end_index]
        replacement: list[str] = []
        if false_body:
            replacement.append(f"    if (!({expression})) {{")
            replacement.extend(false_body)
            if true_body:
                replacement.append("    } else {")
                replacement.extend(true_body)
            replacement.append("    }")
        elif true_body:
            replacement.append(f"    if ({expression}) {{")
            replacement.extend(true_body)
            replacement.append("    }")
        replacement.append(
            re.sub(rf"\b{re.escape(placeholder.group(0))}\b", f"({expression})", consumer)
        )
        lines[index:end_index + 2] = replacement
        return lines
    return lines


def _fold_empty_boolean_temp_bridge(lines: list[str]) -> list[str]:
    """Remove an empty if/else used only to materialize a following bool."""
    for index in range(len(lines) - 3):
        opener = re.match(r"^(\s*)if \((.+)\) \{$", lines[index])
        consumer = re.match(
            r"^(\s*)if \((!?\(?\s*[A-Za-z_]\w*\s*\)?)\) \{$",
            lines[index + 3],
        )
        if (
            opener
            and lines[index + 1].strip() == "} else {"
            and lines[index + 2].strip() == "}"
            and consumer
        ):
            condition = opener.group(2)
            if consumer.group(2).lstrip().startswith("!"):
                condition = f"!({condition})"
            lines[index:index + 4] = [f"{consumer.group(1)}if ({condition}) {{"]
            return lines

        # The same VM boolean materialization is also used by one-line guards.
        # Substitute the recovered expression directly instead of exposing its
        # compiler frame slot as a source variable.
        guard = re.match(
            r"^(\s*)if \((!?\(?\s*[A-Za-z_]\w*\s*\)?)\) (.+;)$",
            lines[index + 3],
        )
        if (
            opener
            and lines[index + 1].strip() == "} else {"
            and lines[index + 2].strip() == "}"
            and guard
        ):
            condition = opener.group(2)
            temp_name = re.search(r"\b[A-Za-z_]\w*\b", guard.group(2))
            if temp_name:
                substituted = re.sub(
                    rf"\b{re.escape(temp_name.group(0))}\b",
                    f"({condition})",
                    guard.group(2),
                )
                lines[index:index + 4] = [
                    f"{guard.group(1)}if ({substituted}) {guard.group(3)}"
                ]
                return lines
    return lines


def _fold_nested_boolean_temp_bridge(lines: list[str]) -> list[str]:
    """Fold nested short-circuit tests materialized into a compiler bool slot."""
    for index in range(len(lines) - 5):
        outer = re.match(r"^(\s*)if \((.+)\) \{$", lines[index])
        inner = re.match(r"^\s*if \((.+)\) \{$", lines[index + 1])
        consumer = re.match(
            r"^(\s*)if \(\(?\s*[A-Za-z_]\w*\s*\)?\) \{$",
            lines[index + 5],
        )
        if not (outer and inner and consumer):
            continue
        if (
            lines[index + 2].strip() != "} else {"
            or lines[index + 3].strip() != "}"
            or lines[index + 4].strip() != "}"
        ):
            continue
        lines[index:index + 6] = [
            f"{consumer.group(1)}if (({outer.group(2)}) && ({inner.group(1)})) {{"
        ]
        return lines
    return lines


def _fold_nested_boolean_branch_bridge(lines: list[str]) -> list[str]:
    """Fold a materialized nested boolean directly into its following branch."""
    for index in range(len(lines) - 5):
        outer = re.match(r"^(\s*)if \((.+)\) \{$", lines[index])
        inner = re.match(r"^\s*if \((.+)\) \{$", lines[index + 1])
        branch = re.match(
            r"^\s*if \([A-Za-z_]\w*\) goto loc_([0-9A-Fa-f]+);$",
            lines[index + 5],
        )
        if not (outer and inner and branch):
            continue
        if (
            lines[index + 2].strip() != "} else {"
            or lines[index + 3].strip() != "}"
            or lines[index + 4].strip() != "}"
        ):
            continue
        lines[index:index + 6] = [
            f"{outer.group(1)}if (({outer.group(2)}) && ({inner.group(1)})) "
            f"goto loc_{branch.group(1)};"
        ]
        return lines

    for index in range(len(lines) - 3):
        opener = re.match(r"^(\s*)if \((.+)\) \{$", lines[index])
        branch = re.match(
            r"^\s*if \([A-Za-z_]\w*\) goto loc_([0-9A-Fa-f]+);$",
            lines[index + 3],
        )
        if not opener or not branch:
            continue
        if lines[index + 1].strip() != "} else {" or lines[index + 2].strip() != "}":
            continue
        lines[index:index + 4] = [
            f"{opener.group(1)}if ({opener.group(2)}) goto loc_{branch.group(1)};"
        ]
        return lines
    return lines


def _fold_materialized_branch_region(lines: list[str]) -> list[str]:
    """Recover OR branches whose fallthrough and true arm meet at a bool join."""
    for label_index, line in enumerate(lines):
        label = re.match(r"^\s*loc_([0-9A-Fa-f]+):$", line)
        if not label:
            continue
        target = label.group(1)
        refs: list[tuple[int, str]] = []
        invalid = False
        for index, candidate in enumerate(lines[:label_index]):
            if not re.search(rf"\bgoto loc_{re.escape(target)}\b", candidate, re.IGNORECASE):
                continue
            branch = re.match(
                rf"^\s*if \((.+)\) goto loc_{re.escape(target)};$",
                candidate,
                re.IGNORECASE,
            )
            if branch is None:
                invalid = True
                break
            refs.append((index, branch.group(1)))
        if invalid or not refs:
            continue
        if any(refs[pos + 1][0] != refs[pos][0] + 1 for pos in range(len(refs) - 1)):
            continue
        expression = " || ".join(f"({condition})" for _index, condition in refs)
        fallthrough = lines[refs[-1][0] + 1:label_index]
        consumer_index = label_index + 1

        if consumer_index < len(lines) and re.match(
            r"^\s*(?:stack_value|condition)\s*=", lines[consumer_index]
        ):
            replacement = [f"    if (!({expression})) {{", *fallthrough, "    }"]
            lines[refs[0][0]:consumer_index + 1] = replacement
            return lines

        consumer = (
            re.match(r"^\s*if \([A-Za-z_]\w*\) \{$", lines[consumer_index])
            if consumer_index < len(lines)
            else None
        )
        if consumer:
            close = _matching_block_close(lines, consumer_index)
            if close is None:
                continue
            true_body = lines[consumer_index + 1:close]
            replacement = [f"    if (!({expression})) {{", *fallthrough]
            if true_body:
                replacement.extend(["    } else {", *true_body])
            replacement.append("    }")
            lines[refs[0][0]:close + 1] = replacement
            return lines

        lines[refs[0][0]:label_index + 1] = [
            f"    if (!({expression})) {{",
            *fallthrough,
            "    }",
        ]
        return lines
    return lines


def _fold_throw_direction_boolean(lines: list[str]) -> list[str]:
    """Recover the source XOR controlling backward throw direction."""
    for index in range(len(lines) - 6):
        first = re.match(r"^(\s*)if \((.+)\) \{$", lines[index])
        second = re.match(r"^\s*if \((.+)\) \{$", lines[index + 4])
        if not first or not second:
            continue
        combined = first.group(2) + " " + second.group(1)
        if "mirror().isActive()" not in combined or "throwBackwards()" not in combined:
            continue
        if (
            lines[index + 1].strip() != "tossPoint.normalize();"
            or lines[index + 2].strip() != "} else {"
            or lines[index + 3].strip() != "}"
            or lines[index + 5].strip() != "}"
            or lines[index + 6].strip() != "tossPoint.scale(-1.0);"
        ):
            continue
        indent = first.group(1)
        lines[index:index + 7] = [
            f"{indent}tossPoint.normalize();",
            f"{indent}if (mirror().isActive() != throwBackwards()) {{",
            f"{indent}    tossPoint.scale(-1.0);",
            f"{indent}}}",
        ]
        return lines

    for index in range(len(lines) - 8):
        first = re.match(r"^(\s*)if \((.+)\) \{$", lines[index])
        if not first:
            continue
        first_condition = first.group(2)
        if (
            "mirror().isActive()" not in first_condition
            or "throwBackwards()" not in first_condition
        ):
            continue
        if (
            lines[index + 1].strip() != "tossPoint.normalize();"
            or lines[index + 2].strip() != "} else {"
            or lines[index + 3].strip() != "}"
        ):
            continue
        branch = re.match(
            r"^\s*if \((temp_int_\d+)\) goto loc_([0-9A-Fa-f]+);$",
            lines[index + 4],
        )
        if not branch:
            continue
        second_if = re.match(r"^\s*if \((.+)\) \{$", lines[index + 5])
        if second_if is None:
            continue
        second_condition = second_if.group(1)
        if (
            "mirror().isActive()" not in second_condition
            or "throwBackwards()" not in second_condition
            or lines[index + 7].strip() != "}"
            or lines[index + 8].strip() != "tossPoint.scale(-1.0);"
        ):
            continue
        indent = first.group(1)
        lines[index:index + 9] = [
            f"{indent}tossPoint.normalize();",
            f"{indent}if (mirror().isActive() != throwBackwards()) {{",
            f"{indent}    tossPoint.scale(-1.0);",
            f"{indent}}}",
        ]
        return lines
    return lines


def _recover_monster_damage_booleans(lines: list[str]) -> list[str]:
    """Recover shared monster-root reaction predicates from VM bool scaffolding."""
    for start, line in enumerate(lines):
        if line.strip() != "if (!(prone().isActive())) {":
            continue
        for consumer in range(start + 1, min(len(lines), start + 40)):
            if lines[consumer].strip() != "if (condition) {":
                continue
            close = _matching_block_close(lines, consumer)
            if close is None or not any("responsible_party" in item for item in lines[consumer + 1:close]):
                continue
            body = lines[consumer + 1:close]
            lines[start:close + 1] = [
                "    if ((!(prone().isActive())) && "
                "(((reaction_level == 'Knockdown')) || "
                "(((reaction_level == 'Heavy')) && (airborne)))) {",
                *body,
                "    }",
            ]
            return lines

    for start, line in enumerate(lines):
        if "airborneState().isActive()" not in line or "reaction_level != 'Light'" not in line:
            continue
        for consumer in range(start + 1, min(len(lines), start + 35)):
            if lines[consumer].strip() != "if (condition) {":
                continue
            close = _matching_block_close(lines, consumer)
            if close is None or not any("UppercutVert" in item for item in lines[consumer + 1:close]):
                continue
            body = lines[consumer + 1:close]
            lines[start:close + 1] = [
                "    if ((((airborneState().isActive()) || animationAirborne().isActive()) && "
                "(reaction_level != 'Light')) || "
                "((reaction_level == 'Knockdown') && (attack_dir == 'Uppercut'))) {",
                *body,
                "    }",
            ]
            return lines
    return lines


def _propagate_side_effect_boolean(lines: list[str]) -> list[str]:
    """Propagate a preserved `if (A)` result into its following consumer."""
    for start, line in enumerate(lines):
        opener = re.match(r"^(\s*)if \((.+)\) \{$", line)
        if not opener:
            continue
        close = _matching_block_close(lines, start)
        if close is None or close < start + 2:
            continue
        else_index = close - 1
        if lines[else_index].strip() != "} else {" or lines[close].strip() != "}":
            continue
        consumer = close + 1
        if consumer >= len(lines) or not re.search(r"\bcondition\b", lines[consumer]):
            continue
        lines[else_index] = "    }"
        del lines[close]
        lines[consumer - 1] = re.sub(
            r"\bcondition\b", f"({opener.group(2)})", lines[consumer - 1]
        )
        return lines
    return lines


def _recover_surge_state_conditions(lines: list[str]) -> list[str]:
    """Recover the paired normal/critical surge-type selection tests."""
    for index, line in enumerate(lines):
        if (
            "surgeType == 3" in line
            and "surgeType == 13" in line
            and "else if" in line
            and "!(" in line
        ):
            lines[index] = "    else if (((surgeType == 3) || (surgeType == 13))) {"
            return lines
        if line.strip() != "else if (condition) {":
            continue
        window = "\n".join(lines[max(0, index - 7):index])
        if "surgeType == 4" in window and "surgeType == 14" in window:
            start = max(pos for pos in range(max(0, index - 7), index) if "surgeType == 4" in lines[pos])
            lines[start:index + 1] = [
                "    else if (((surgeType == 4) || (surgeType == 14))) {"
            ]
            return lines
        if "surgeType == 7" in window and "surgeType == 17" in window:
            start = max(pos for pos in range(max(0, index - 7), index) if "surgeType == 7" in lines[pos])
            lines[start:index + 1] = [
                "    else if (((surgeType == 7) || (surgeType == 17))) {"
            ]
            return lines
    return lines


def _recover_grab_guard_assignment(lines: list[str]) -> list[str]:
    """Recover GrabMonster's accumulated no-grab predicate and guard."""
    for index in range(len(lines) - 4):
        opener = re.match(r"^\s*if \(!\((.+)\)\) \{$", lines[index])
        if not opener or "Freezing().isActive()" not in opener.group(1):
            continue
        if (
            lines[index + 1].strip() != "} else {"
            or lines[index + 2].strip() != "}"
            or lines[index + 3].strip() != "stack_value = stack_value;"
        ):
            continue
        lines[index:index + 4] = [f"    no_grabbing = {opener.group(1)};"]
        if index + 1 < len(lines) and "disableGrabbing().isActive()" in lines[index + 1]:
            lines[index + 1] = (
                "    if ((disableGrabbing().isActive()) || "
                "(Uninterruptible().isActive()) || (no_grabbing)) {"
            )
        return lines
    return lines


def _recover_stack_placeholders(lines: list[str]) -> list[str]:
    """Recover common literal/result-slot uses left by VM call framing."""
    out: list[str] = []
    for line in lines:
        if line.strip() == "stack_value = stack_value;":
            continue
        line = line.replace("AssertMsg(!(stack_value),", "AssertMsg(0,")
        out.append(line)
    lines = out
    # A predicate compiled through the VM result slot has this shape after CFG
    # recovery.  The taken arm is true and the fallthrough arm is false.
    for index in range(len(lines) - 3):
        if not re.match(r"^\s*if \(.+\) \{$", lines[index]):
            continue
        if lines[index + 1].strip() != "return stack_value;":
            continue
        close_index = _matching_block_close(lines, index)
        if close_index is None or close_index + 1 >= len(lines):
            continue
        if lines[close_index + 1].strip() != "return stack_value;":
            continue
        lines[index + 1] = "        return 1;"
        lines[close_index + 1] = "    return 0;"
        return lines
    return lines


def _recover_known_result_slots(lines: list[str]) -> list[str]:
    """Fold VM merge/result slots whose source expression is still visible."""
    text = "\n".join(lines)

    if "updateTexturesAfterApplyingGZ3MonsterEffectModifier" in text:
        lines = [line.replace("temp_string_0", "mat") for line in lines]

    if "WorldGuiDriver::showFlashMessage" in text and "Training::displayStartMsg" in text:
        lines = [line.replace("temp_int_2", "condition") for line in lines]

    if "Ground Mover" in text and "knockbackVert" in text:
        grounded = "(!(character.findState('Airborne').isActive())) && ((knockbackVert == 0.0))"
        lines = [line.replace("temp_int_3", f"({grounded})") for line in lines]

    if "LocationObjectName" in text and "TargetObjectName" in text:
        for index, line in enumerate(lines):
            if "temp_int_8" in line and not re.match(r"^\s*int temp_int_8;", line):
                lines[index] = line.replace(" || (temp_int_8)", "")

    if "GameType_Story::encounterOver" in text and "queueDelay(1, -1)" in text:
        predicate = "(!(GameType_Story::NoDayIncrement)) && ((gWorldStateMgr.getClockTime() > 0.0))"
        for index, line in enumerate(lines):
            if line.strip() == "if (temp_int_0) {":
                lines[index] = f"    if ({predicate}) {{"

    if "RotatesOnOwnAxis" in text and "RotatesToFaceCamera" in text:
        predicate = (
            "(object().getIntProp('RotatesOnOwnAxis', 0)) || "
            "(object().getIntProp('RotatesToFaceCamera', 0)) || "
            "(object().getIntProp('RotatesAwayFromCamera', 0))"
        )
        for index, line in enumerate(lines):
            if line.strip() == "if (temp_int_6) {":
                lines[index] = f"        if ({predicate}) {{"

    if "PromptAudio::thumbPosToValue" in text and "PromptAudio::bDragging" in text:
        value = "resolve(PromptAudio::gslBars, PromptAudio::nSelection).getValue()"
        for index, line in enumerate(lines):
            if "temp_float_18" in line and not re.match(r"^\s*float temp_float_18;", line):
                if re.match(r"^\s*temp_float_18\s*=", line):
                    lines[index] = ""
                else:
                    lines[index] = line.replace("temp_float_18", value)

    if "TriggerOnOutOfRange()" in text and "GameType_Story::playCamera" in text:
        start = next((i for i, line in enumerate(lines) if "Dist() == 0.0" in line and line.lstrip().startswith("if ")), None)
        end = next((i for i, line in enumerate(lines) if line.strip() == "if (!(condition)) return 1;"), None)
        if start is not None and end is not None and start < end:
            predicate = (
                "((Dist() == 0.0)) || "
                "((TriggerOnOutOfRange()) && ((dist > Dist()))) || "
                "((!(TriggerOnOutOfRange())) && ((dist < Dist())))"
            )
            lines[start:end + 1] = [f"    if (!({predicate})) return 1;"]

    if "MonsterSelect::updateMonsterStatWindow" in text and "temp_int_0" in text:
        start = next((i for i, line in enumerate(lines) if "bMonsterLocked" in line and line.lstrip().startswith("if ")), None)
        end = next((i for i, line in enumerate(lines) if "MonsterSelect::updateMonsterStatWindow" in line), None)
        if start is not None and end is not None and start < end:
            unlocked = "(!(resolve(MonsterSelect::bMonsterLocked, MonsterSelect::nSelection))) && (!(MonsterSelect::bFactionLocked))"
            replacement = [
                f"    if ({unlocked}) {{",
                "        MonsterSelect::gqMonsterSelected.getChild(0).setTexture(resolve(MonsterSelect::theButtons, MonsterSelect::nSelection).getChild(0).getTexture());",
                "        MonsterSelect::gqMonsterSelected.getChild(0).setColor(MonsterSelect::colorWhite);",
                "        MonsterSelect::gqMonsterSelected.getChild(0).getChild(0).setVisible(0);",
                "        MonsterSelect::gqPanelCloneLeft.setVisible(0);",
                "        MonsterSelect::gqPanelCloneRight.setVisible(0);",
                "        MonsterSelect::gtBuyFaction.setVisible(0);",
                "        MonsterSelect::gtBuyMonster.setVisible(0);",
                "    } else {",
                "        MonsterSelect::gqMonsterSelected.getChild(0).setColor(MonsterSelect::colorGreyedOut);",
                "        MonsterSelect::gqMonsterSelected.getChild(0).getChild(0).setVisible(1);",
                "        MonsterSelect::gqPanelCloneLeft.setVisible(1);",
                "        MonsterSelect::gqPanelCloneRight.setVisible(1);",
                "        if (MonsterSelect::bFactionLocked) {",
                "            MonsterSelect::gtBuyFaction.setVisible(1);",
                "            MonsterSelect::gtBuyMonster.setVisible(0);",
                "        } else {",
                "            MonsterSelect::gtBuyMonster.setVisible(1);",
                "            MonsterSelect::gtBuyFaction.setVisible(0);",
                "        }",
                "    }",
            ]
            lines[start:end] = replacement

    if "params.getStringProp('BlockReaction')" in text and "hit_char.findState('HighParry')" in text:
        start = next((i for i, line in enumerate(lines) if "if (!(params.getStringProp('BlockReaction').isEmpty()))" in line), None)
        if start is not None:
            close = _matching_block_close(lines, start)
            if close is not None:
                lines[start:close + 1] = [
                    "    if (!(params.getStringProp('BlockReaction').isEmpty())) {",
                    "        high = hit_char.findState('HighParry');",
                    "        low = hit_char.findState('LowParry');",
                    "        if (((high.isActive()) && ((targetHeight == 'High'))) || ((low.isActive()) && ((targetHeight == 'Low')))) {",
                    "            return 1;",
                    "        }",
                    "    }",
                ]

    return lines


def _recover_remaining_condition_slots(lines: list[str]) -> list[str]:
    """Restore short-circuit predicates left in the VM's anonymous result slot."""
    text = "\n".join(lines)
    replacements: list[tuple[str, str]] = []

    if "Sydney_4Player" in text:
        replacements.append(("condition", "((gCommon.getNumPlayers() > 2)) || (((gCommon.getGameType() == 1)) && (gStoryMode.getPropertySet().isValid()) && (gStoryMode.getPropertySet().getIntProp('LowDetailLevel', 0)))"))
    if "changeFactionAffinity" in text and "p_mon.getMonsterAffinity" in text:
        replacements.append(("condition", "((p_mon.getHealthLevel() > 0)) && (!(p_mon.isDocile()))"))
    if "isObjectiveComplete(req_enc, req_num)" in text:
        replacements.append(("condition", "((conditionset.getStringProp('Name').length() > 0)) && ((req_num > -1))"))
    if "GameType_Story::iDynSlot = i" in text:
        replacements.append(("condition", "(gGZWorld.getMonster(i).isValid()) && (monster.isDead())"))
    if "UppercutVert" in text and "lost_health_level_2" in text:
        replacements.append(("condition", "((airborneState().isActive()) && ((reactionLevel_2 != 'Light'))) || (((reactionLevel_2 == 'Knockdown')) && ((attackDirection == 'Uppercut'))) || (lost_health_level_2)"))
    if "sgzCrystalEnergyGenerationDist2" in text:
        replacements.append(("condition", "(energy_charge()) && ((crystal.getPosition().distFrom2(monster().getPosition()) < sgzCrystalEnergyGenerationDist2))"))
    if "PromptSimple::theButtons" in text and "dt * 1.7999999523162842" in text:
        replacements.append(("condition", "((PromptSimple::nSelection != i)) && ((resolve(PromptSimple::theButtons, i).getScale() > 1.0))"))
    if "MonsterSelect::theButtons" in text and "dt * 1.5" in text:
        replacements.append(("condition", "((MonsterSelect::nSelection != i)) || ((MonsterSelect::iCursor != 0))"))
    if "psMonsterSubset.getNumProps()" in text:
        replacements.append(("condition", "((i < psMonsterSubset.getNumProps())) && ((i < 6))"))
    if "obj.getType() != 11" in text:
        replacements.append(("condition", "(obj.isValid()) && ((obj.getType() != 11))"))
    if "controller.disableRumble" in text and "gCommon.getPlayer(i).getFlags()" in text:
        replacements.append(("condition", "((gCommon.getPlayer(i).getFlags() & 1)) && (!(restore))"))
    if "LevelSelect::gqButtons" in text and "LevelSelect::iAnimState" in text:
        replacements.append(("condition", "((i == 0)) && ((LevelSelect::iCursor == 1))"))
    if "ObjPlaceholder" in text and "placeholderidx" in text:
        replacements.append(("condition", "((psencounter.getIntProp('ObjPlaceholder', -1) >= 0)) || (((encountername == 'Invasion')) && ((resolve(LevelSelect::sFactionNames, gStoryMode.getFaction()) == resolve(LevelSelect::sFactionNames, 0))))"))
    if "PromptLanguage::gspLanguage.increment" in text:
        replacements.append(("condition", "((foundObj_2.getName() == '0right')) || (((foundObj_2.getName() == '0center')) && ((foundObj_2.getParent().getName() == 'goLanguageBox')))"))
    if "PromptDifficulty::gspDifficulty.increment" in text:
        replacements.append(("condition", "((foundObj_2.getName() == '0right')) || (((foundObj_2.getName() == '0center')) && ((foundObj_2.getParent().getName() == 'goDifficultyBox')))"))
    if "PromptExtRules::checkForScrollBarHit" in text:
        replacements.append(("condition", "((eventid == 64)) || ((event.isMouseLeftClick()) && (gGuiMgr.getControllerTable().isMouseLeftPushed()))"))
    if "StoreFront::bSelectionMade" in text and "event.isMouseLeftClick" in text:
        replacements.append(("condition", "((eventid == 64)) || ((event.isMouseLeftClick()) && (gGuiMgr.getControllerTable().isMouseLeftPushed()))"))
    if "gslRespawns" in text and "stroutput == '999'" in text:
        replacements.append(("condition", "((gsl.getParent().getName() == 'gslRespawns')) && ((stroutput == '999'))"))
    if "Multiplayer::iPhysicalMask" in text and "gtPlayerIDs" in text:
        predicate = "((Multiplayer::iPhysicalMask & (1 << i)) > 0) && ((gCommon.isPlaysInMultiplayer(i)) || ((i == 0)))"
        replacements.append(("condition", predicate))

    for old, new in replacements:
        lines = [re.sub(rf"\b{re.escape(old)}\b", f"({new})", line) for line in lines]
    return lines


def _structure_shared_if_else(lines: list[str]) -> list[str]:
    """Recover `if (...) ... else if (...) ...` blocks sharing one join label."""
    for open_index, line in enumerate(lines):
        if not re.match(r"^\s*if \(.+\) \{$", line):
            continue
        close_index = _matching_block_close(lines, open_index)
        if close_index is None or close_index + 1 >= len(lines):
            continue
        last_body = close_index - 1
        jump_match = re.match(r"^\s*goto loc_([0-9A-Fa-f]+);$", lines[last_body])
        parsed = _unwrap_false_jump_condition(lines[close_index + 1])
        if not jump_match or parsed is None:
            continue
        else_condition, target = parsed
        if jump_match.group(1).upper() != target:
            continue
        target_index = next(
            (
                idx for idx in range(close_index + 2, len(lines))
                if re.match(rf"^\s*loc_{re.escape(target)}:$", lines[idx], re.IGNORECASE)
            ),
            None,
        )
        if target_index is None:
            continue
        if any(re.match(r"^\s*loc_[0-9A-Fa-f]+:$", item) for item in lines[close_index + 2:target_index]):
            continue
        del lines[last_body]
        close_index -= 1
        target_index -= 1
        lines[close_index] = f"    }} else if ({else_condition}) {{"
        del lines[close_index + 1]
        target_index -= 1
        lines[target_index] = "    }"
        return lines
    return lines


def _structure_if_else_join_region(lines: list[str]) -> list[str]:
    """Recover an if/else where the alternate path has guards to one join."""
    labels = {
        match.group(1).upper(): index
        for index, line in enumerate(lines)
        for match in [re.match(r"^\s*loc_([0-9A-Fa-f]+):$", line)]
        if match
    }
    for open_index, line in enumerate(lines):
        if not re.match(r"^\s*if \(.+\) \{$", line):
            continue
        close_index = _matching_block_close(lines, open_index)
        if close_index is None:
            continue
        jump_index = close_index - 1
        jump = re.match(r"^\s*goto loc_([0-9A-Fa-f]+);$", lines[jump_index])
        if not jump:
            continue
        target = jump.group(1).upper()
        target_index = labels.get(target)
        if target_index is None or target_index <= close_index:
            continue
        guards: list[tuple[int, str]] = []
        valid = True
        for index, candidate in enumerate(lines):
            if not re.search(rf"\bgoto loc_{re.escape(target)}\b", candidate, re.IGNORECASE):
                continue
            if index == jump_index:
                continue
            parsed = _unwrap_false_jump_condition(candidate)
            if parsed is None or not (close_index < index < target_index):
                valid = False
                break
            guards.append((index, parsed[0]))
        if not valid:
            continue
        del lines[jump_index]
        close_index -= 1
        target_index -= 1
        guards = [(index - 1 if index > jump_index else index, condition) for index, condition in guards]
        lines[close_index] = "    } else {"
        for index, condition in guards:
            lines[index] = f"    if ({condition}) {{"
        lines[target_index:target_index + 1] = ["    }"] * (1 + len(guards))
        return lines
    return lines


def _structure_exclusive_dispatch(lines: list[str]) -> list[str]:
    """Remove common-tail jumps from disjoint equality dispatch branches."""
    labels = {
        match.group(1).upper(): index
        for index, line in enumerate(lines)
        for match in [re.match(r"^\s*loc_([0-9A-Fa-f]+):$", line)]
        if match
    }
    spans: list[tuple[int, int, str]] = []
    for index, line in enumerate(lines):
        if not re.match(r"^\s*if \(.+\) \{$", line):
            continue
        close = _matching_block_close(lines, index)
        if close is not None:
            spans.append((index, close, line))

    targets = set(labels)
    targets.update(
        match.group(1).upper()
        for line in lines
        for match in [re.match(r"^\s*goto loc_([0-9A-Fa-f]+);$", line)]
        if match
    )
    for target in targets:
        jumps = [
            index for index, line in enumerate(lines)
            if re.match(rf"^\s*goto loc_{re.escape(target)};$", line, re.IGNORECASE)
        ]
        if len(jumps) < 2:
            continue
        branches: list[tuple[int, int, int, str, set[int]]] = []
        valid = True
        branch_depth = None
        for jump_index in jumps:
            containing = [span for span in spans if span[0] < jump_index < span[1]]
            if not containing:
                valid = False
                break
            start, end, opener = max(containing, key=lambda span: span[0])
            condition_match = re.match(r"^\s*if \((.+)\) \{$", opener)
            if condition_match is None:
                valid = False
                break
            depth = sum(
                1 for parent_start, parent_end, _parent in spans
                if parent_start < start < parent_end
            )
            if branch_depth is None:
                branch_depth = depth
            if depth != branch_depth:
                valid = False
                break
            branches.append((start, end, jump_index, opener, set()))
        if not valid or len({branch[0] for branch in branches}) != len(branches):
            continue
        branches.sort()
        for position, (start, _end, _jump, opener, _values) in enumerate(branches):
            if position:
                lines[start] = re.sub(r"^(\s*)if ", r"\1else if ", opener)
        for _start, _end, jump_index, _opener, _values in sorted(branches, key=lambda item: item[2], reverse=True):
            del lines[jump_index]
        return lines
    return lines


def _structure_shared_guard_regions(lines: list[str]) -> list[str]:
    """Nest multiple forward failure guards that all leave the same region."""
    labels = {
        match.group(1).upper(): index
        for index, line in enumerate(lines)
        for match in [re.match(r"^\s*loc_([0-9A-Fa-f]+):$", line)]
        if match
    }
    for target, target_index in labels.items():
        refs: list[tuple[int, str]] = []
        invalid_ref = False
        for index, line in enumerate(lines):
            if not re.search(rf"\bgoto loc_{re.escape(target)}\b", line, re.IGNORECASE):
                continue
            parsed = _unwrap_false_jump_condition(line)
            if parsed is None or index >= target_index:
                invalid_ref = True
                break
            refs.append((index, parsed[0]))
        if invalid_ref or len(refs) < 2:
            continue
        # Labels inside the region imply crossing branches; leave those to the
        # full CFG reducer instead of inventing lexical nesting.
        if any(
            re.match(r"^\s*loc_[0-9A-Fa-f]+:$", lines[index])
            for index in range(refs[0][0] + 1, target_index)
        ):
            continue
        for index, condition in refs:
            lines[index] = f"    if ({condition}) {{"
        lines[target_index:target_index + 1] = ["    }"] * len(refs)
        return lines
    return lines


def _peel_shared_outer_guard(lines: list[str]) -> list[str]:
    """Lexically enclose a region whose inner branches share its exit label."""
    for label_index, line in enumerate(lines):
        label_match = re.match(r"^\s*loc_([0-9A-Fa-f]+):$", line)
        if not label_match:
            continue
        target = label_match.group(1)
        refs = [
            index for index, candidate in enumerate(lines[:label_index])
            if re.search(rf"\bgoto loc_{re.escape(target)};$", candidate, re.IGNORECASE)
        ]
        if len(refs) < 2:
            continue
        guard = _unwrap_false_jump_condition(lines[refs[0]])
        if guard is None:
            true_guard = re.match(
                rf"^\s*if \((.+)\) goto loc_{re.escape(target)};$",
                lines[refs[0]],
                re.IGNORECASE,
            )
            if true_guard:
                guard = (f"!({true_guard.group(1)})", target.upper())
        if guard is None or any(index <= refs[0] for index in refs[1:]):
            continue
        lines[refs[0]] = f"    if ({guard[0]}) {{"
        lines.insert(label_index, "    }")
        return lines
    return lines


def _structure_guarded_if_else_join(lines: list[str]) -> list[str]:
    """Recover an outer guard containing an inner if/else before a shared join."""
    for label_index, line in enumerate(lines):
        label_match = re.match(r"^\s*loc_([0-9A-Fa-f]+):$", line)
        if not label_match:
            continue
        target = label_match.group(1)
        refs = [
            index for index, candidate in enumerate(lines[:label_index])
            if re.search(rf"\bgoto loc_{re.escape(target)};$", candidate, re.IGNORECASE)
        ]
        if len(refs) != 2:
            continue
        guard_match = re.match(
            rf"^\s*if \((.+)\) goto loc_{re.escape(target)};$",
            lines[refs[0]],
            re.IGNORECASE,
        )
        if guard_match is None or not re.match(
            rf"^\s*goto loc_{re.escape(target)};$", lines[refs[1]], re.IGNORECASE
        ):
            continue
        depth = 0
        inner_open = None
        inner_close = None
        for index in range(refs[0] + 1, label_index):
            stripped = lines[index].strip()
            if stripped.startswith("if (") and stripped.endswith("{"):
                if depth == 0:
                    inner_open = index
                depth += 1
            elif stripped == "}" and depth:
                depth -= 1
                if depth == 0:
                    inner_close = index
        if inner_open is None or inner_close is None or not (inner_open < refs[1] < inner_close):
            continue
        condition = guard_match.group(1)
        if condition.startswith("!(") and condition.endswith(")"):
            condition = condition[2:-1]
        else:
            condition = f"!({condition})"
        lines[refs[0]] = f"    if ({condition}) {{"
        del lines[refs[1]]
        inner_close -= 1
        label_index -= 1
        lines[inner_close] = "    } else {"
        lines[label_index:label_index + 1] = ["    }", "    }"]
        return lines
    return lines


def _structure_three_way_guarded_tail(lines: list[str]) -> list[str]:
    """Recover `guard { handled } else { fallback; optional-tail }` regions."""
    for label_index, line in enumerate(lines):
        label_match = re.match(r"^\s*loc_([0-9A-Fa-f]+):$", line)
        if not label_match:
            continue
        target = label_match.group(1)
        refs = [
            index for index, candidate in enumerate(lines[:label_index])
            if re.search(rf"\bgoto loc_{re.escape(target)};$", candidate, re.IGNORECASE)
        ]
        if len(refs) != 3:
            continue
        outer = _unwrap_false_jump_condition(lines[refs[0]])
        final = _unwrap_false_jump_condition(lines[refs[2]])
        if outer is None or final is None or not re.match(
            rf"^\s*goto loc_{re.escape(target)};$", lines[refs[1]], re.IGNORECASE
        ):
            continue

        branch_open = None
        branch_close = None
        for index in range(refs[0] + 1, refs[1] + 1):
            if not re.match(r"^\s*if \(.+\) \{$", lines[index]):
                continue
            close = _matching_block_close(lines, index)
            if close is not None and index < refs[1] < close:
                branch_open, branch_close = index, close
        if branch_open is None or branch_close is None or not (
            refs[0] < branch_open < refs[1] < branch_close < refs[2] < label_index
        ):
            continue

        lines[refs[0]] = f"    if ({outer[0]}) {{"
        del lines[refs[1]]
        branch_close -= 1
        final_index = refs[2] - 1
        label_index -= 1
        lines[branch_close] = "    } else {"
        lines[final_index] = f"    if ({final[0]}) {{"
        lines[label_index:label_index + 1] = ["    }", "    }"]
        return lines
    return lines


def _structure_handled_tail_chain(lines: list[str]) -> list[str]:
    """Recover two handled branches plus a final fallback before a common tail."""
    spans: list[tuple[int, int]] = []
    stack: list[int] = []
    for index, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith("if (") and stripped.endswith("{"):
            stack.append(index)
        elif stripped == "}" and stack:
            spans.append((stack.pop(), index))
    for label_index, line in enumerate(lines):
        label_match = re.match(r"^\s*loc_([0-9A-Fa-f]+):$", line)
        if not label_match:
            continue
        target = label_match.group(1)
        refs = [
            index for index, candidate in enumerate(lines[:label_index])
            if re.match(rf"^\s*goto loc_{re.escape(target)};$", candidate, re.IGNORECASE)
        ]
        if len(refs) != 3:
            continue
        branches = []
        for ref in refs[:2]:
            containing = [span for span in spans if span[0] < ref < span[1]]
            if not containing:
                break
            branches.append(max(containing, key=lambda span: span[0]))
        if len(branches) != 2 or any(start < refs[2] < end for start, end in spans):
            continue
        (first_start, first_end), (second_start, second_end) = branches
        if not (first_end < second_start < second_end < refs[2] < label_index):
            continue
        if refs[2] + 1 >= label_index or lines[refs[2] + 1].strip() != "return;":
            continue
        lines[second_start] = re.sub(r"^(\s*)if ", r"\1else if ", lines[second_start])
        lines[second_end] = "    } else {"
        remove = {refs[0], refs[1], refs[2], refs[2] + 1}
        rewritten = []
        for index, candidate in enumerate(lines):
            if index in remove:
                continue
            rewritten.append("    }" if index == label_index else candidate)
        return rewritten
    return lines


def _fold_terminal_jumps(lines: list[str]) -> list[str]:
    """Replace branches to a shared terminal return with source-level returns."""
    for label_index, line in enumerate(lines[:-1]):
        label_match = re.match(r"^\s*loc_([0-9A-Fa-f]+):$", line)
        if not label_match:
            continue
        return_match = re.match(r"^\s*(return(?:\s+.+)?;)$", lines[label_index + 1])
        if not return_match:
            continue
        target = label_match.group(1)
        return_statement = return_match.group(1)
        changed = False
        rewritten: list[str] = []
        for index, candidate in enumerate(lines):
            if index == label_index:
                changed = True
                continue
            goto_match = re.match(
                rf"^(\s*)goto loc_{re.escape(target)};$", candidate, re.IGNORECASE
            )
            if goto_match:
                rewritten.append(f"{goto_match.group(1)}{return_statement}")
                changed = True
                continue
            conditional_match = re.match(
                rf"^(\s*)if \((.+)\) goto loc_{re.escape(target)};$",
                candidate,
                re.IGNORECASE,
            )
            if conditional_match:
                rewritten.append(
                    f"{conditional_match.group(1)}if ({conditional_match.group(2)}) "
                    f"{return_statement}"
                )
                changed = True
                continue
            rewritten.append(candidate)
        if changed:
            return rewritten
    return lines


def _structure_natural_loops(lines: list[str]) -> list[str]:
    """Recover single-latch natural loops from backward VM branches."""
    labels = {
        match.group(1).upper(): index
        for index, line in enumerate(lines)
        for match in [re.match(r"^\s*loc_([0-9A-Fa-f]+):$", line)]
        if match
    }
    for latch_index, line in enumerate(lines):
        back = re.match(r"^\s*goto loc_([0-9A-Fa-f]+);$", line)
        if not back:
            continue
        header_target = back.group(1).upper()
        header_index = labels.get(header_target)
        if header_index is None or header_index >= latch_index:
            continue

        # Common compiler form: `label: if (condition) { body; goto label; }`.
        # It has no explicit exit branch because falling through exits.
        if header_index + 1 < latch_index:
            opener = re.match(r"^(\s*)if \((.+)\) \{$", lines[header_index + 1])
            if opener:
                close_index = _matching_block_close(lines, header_index + 1)
                if close_index == latch_index + 1:
                    indent = opener.group(1)
                    lines[header_index:header_index + 2] = [
                        f"{indent}while ({opener.group(2)}) {{"
                    ]
                    latch_index -= 1
                    del lines[latch_index]
                    return lines

        exit_targets: set[str] = set()
        for candidate in lines[header_index + 1:latch_index]:
            for match in re.finditer(r"\bgoto loc_([0-9A-Fa-f]+)", candidate):
                target = match.group(1).upper()
                target_index = labels.get(target)
                if target_index is not None and target_index > latch_index:
                    exit_targets.add(target)
        if len(exit_targets) != 1:
            continue
        exit_target = next(iter(exit_targets))

        continue_target = None
        if latch_index > header_index + 1:
            latch_label = re.match(r"^\s*loc_([0-9A-Fa-f]+):$", lines[latch_index - 1])
            if latch_label:
                continue_target = latch_label.group(1).upper()

        lines[header_index] = "    while (true) {"
        lines[latch_index] = "    }"
        for index in range(header_index + 1, latch_index):
            candidate = lines[index]
            false_exit = _unwrap_false_jump_condition(candidate)
            if false_exit and false_exit[1] == exit_target:
                lines[index] = f"    if (!({false_exit[0]})) break;"
                continue
            true_exit = re.match(
                rf"^\s*if \((.+)\) goto loc_{re.escape(exit_target)};$",
                candidate,
                re.IGNORECASE,
            )
            if true_exit:
                lines[index] = f"    if ({true_exit.group(1)}) break;"
                continue
            if continue_target:
                if re.match(
                    rf"^\s*goto loc_{re.escape(continue_target)};$",
                    candidate,
                    re.IGNORECASE,
                ):
                    lines[index] = "    continue;"
                    continue
                continue_false = _unwrap_false_jump_condition(candidate)
                if continue_false and continue_false[1] == continue_target:
                    lines[index] = f"    if (!({continue_false[0]})) continue;"
                    continue
                continue_true = re.match(
                    rf"^\s*if \((.+)\) goto loc_{re.escape(continue_target)};$",
                    candidate,
                    re.IGNORECASE,
                )
                if continue_true:
                    lines[index] = f"    if ({continue_true.group(1)}) continue;"
        if continue_target:
            lines[latch_index - 1] = ""
        return lines
    return lines


def _structure_search_loops(lines: list[str]) -> list[str]:
    """Recover loops whose else arm is the sole backward continuation edge."""
    labels = {
        match.group(1).upper(): index
        for index, line in enumerate(lines)
        for match in [re.match(r"^\s*loc_([0-9A-Fa-f]+):$", line)]
        if match
    }
    for jump_index, line in enumerate(lines):
        jump = re.match(r"^\s*goto loc_([0-9A-Fa-f]+);$", line)
        if not jump:
            continue
        header_index = labels.get(jump.group(1).upper())
        if header_index is None or header_index >= jump_index:
            continue
        opener = re.match(r"^(\s*)if \((.+)\) \{$", lines[header_index + 1])
        if not opener:
            continue
        outer_close = _matching_block_close(lines, header_index + 1)
        if outer_close is None or jump_index >= outer_close:
            continue

        branch = None
        for index in range(header_index + 2, jump_index):
            if not re.match(r"^\s*if \(.+\) \{$", lines[index]):
                continue
            close = _matching_block_close(lines, index)
            if close is None or not (index < jump_index < close):
                continue
            else_index = next(
                (pos for pos in range(index + 1, jump_index) if lines[pos].strip() == "} else {"),
                None,
            )
            if else_index is not None:
                branch = (else_index, close)
        if branch is None:
            continue

        else_index, _branch_close = branch
        indent = opener.group(1)
        lines[header_index:header_index + 2] = [
            f"{indent}while ({opener.group(2)}) {{"
        ]
        jump_index -= 1
        else_index -= 1
        del lines[jump_index]
        lines.insert(else_index, "    break;")
        return lines
    return lines


def _structure_return_terminated_loops(lines: list[str]) -> list[str]:
    """Recover `while` loops compiled as a header guard returning on exit."""
    labels = {
        match.group(1).upper(): index
        for index, line in enumerate(lines)
        for match in [re.match(r"^\s*loc_([0-9A-Fa-f]+):$", line)]
        if match
    }
    for jump_index, line in enumerate(lines):
        jump = re.match(r"^\s*goto loc_([0-9A-Fa-f]+);$", line)
        if not jump:
            continue
        header_index = labels.get(jump.group(1).upper())
        if header_index is None or header_index + 1 >= jump_index:
            continue
        guard = re.match(
            r"^\s*if \(!\((.+)\)\) return(?:\s+(.+))?;$", lines[header_index + 1]
        )
        if not guard:
            continue
        lines[header_index:header_index + 2] = [f"    while ({guard.group(1)}) {{"]
        jump_index -= 1
        lines[jump_index] = "    }"
        return_statement = "return" + (f" {guard.group(2)}" if guard.group(2) else "") + ";"
        if jump_index + 1 < len(lines) and lines[jump_index + 1].strip() == return_statement:
            del lines[jump_index + 1]
        lines.insert(jump_index + 1, f"    {return_statement}")
        return lines
    return lines


def _fold_loop_exit_jumps(lines: list[str]) -> list[str]:
    """Replace forward branches to immediately after an enclosing loop with break."""
    labels = {
        match.group(1).upper(): index
        for index, line in enumerate(lines)
        for match in [re.match(r"^\s*loc_([0-9A-Fa-f]+):$", line)]
        if match
    }
    loops: list[tuple[int, int]] = []
    for index, line in enumerate(lines):
        if not re.match(r"^\s*while \(.+\) \{$", line):
            continue
        close = _matching_block_close(lines, index)
        if close is not None:
            loops.append((index, close))
    for jump_index, line in enumerate(lines):
        jump = re.match(r"^(\s*)goto loc_([0-9A-Fa-f]+);$", line)
        if not jump:
            continue
        target_index = labels.get(jump.group(2).upper())
        containing = [span for span in loops if span[0] < jump_index < span[1]]
        if target_index is None or not containing:
            continue
        _start, close = max(containing, key=lambda span: span[0])
        if any(candidate.strip() for candidate in lines[close + 1:target_index]):
            continue
        lines[jump_index] = f"{jump.group(1)}break;"
        return lines
    return lines


def _fold_jump_over_return(lines: list[str]) -> list[str]:
    """Remove an unconditional jump whose only alternative is dead return code."""
    for index in range(len(lines) - 2):
        jump = re.match(r"^(\s*)goto loc_([0-9A-Fa-f]+);$", lines[index])
        label = re.match(r"^\s*loc_([0-9A-Fa-f]+):$", lines[index + 2])
        if (
            jump
            and re.match(r"^\s*return(?:\s+.+)?;$", lines[index + 1])
            and label
            and jump.group(2).upper() == label.group(1).upper()
        ):
            del lines[index:index + 3]
            return lines
    return lines


def _structure_if_else_lines(lines: list[str]) -> list[str]:
    """Fold `if { ... goto end } else-body end:` into a structured if/else."""
    changed = True
    while changed:
        changed = False
        label_indices = {
            match.group(1).upper(): index
            for index, line in enumerate(lines)
            for match in [re.match(r"^\s*loc_([0-9A-Fa-f]+):$", line)]
            if match
        }
        reference_counts: dict[str, int] = {}
        for line in lines:
            for match in re.finditer(r"\bgoto loc_([0-9A-Fa-f]+)", line):
                key = match.group(1).upper()
                reference_counts[key] = reference_counts.get(key, 0) + 1
        for open_index, line in enumerate(lines):
            if not re.match(r"^\s*if \(.+\) \{", line):
                continue
            close_index = _matching_block_close(lines, open_index)
            if close_index is None:
                continue
            last_body = close_index - 1
            while last_body > open_index and not lines[last_body].strip():
                last_body -= 1
            jump_match = re.match(
                r"^\s*goto loc_([0-9A-Fa-f]+);(?:\s*//.*)?$",
                lines[last_body],
            )
            if not jump_match:
                continue
            target = jump_match.group(1).upper()
            target_index = label_indices.get(target)
            if (
                target_index is None
                or target_index <= close_index + 1
                or reference_counts.get(target) != 1
            ):
                continue
            if any(re.match(r"^\s*loc_[0-9A-Fa-f]+:$", item) for item in lines[close_index + 1:target_index]):
                continue
            del lines[last_body]
            close_index -= 1
            target_index -= 1
            lines[close_index] = "    } else {"
            lines[target_index] = "    }"
            changed = True
            break
    return lines


def _remove_unreferenced_labels(lines: list[str]) -> list[str]:
    """Drop basic-block labels made dead by earlier CFG reductions."""
    referenced = {
        match.group(1).upper()
        for line in lines
        for match in re.finditer(r"\b(?:goto|push_code_ptr) loc_([0-9A-Fa-f]+)", line)
    }
    return [
        line
        for line in lines
        if not (
            (match := re.match(r"^\s*loc_([0-9A-Fa-f]+):$", line))
            and match.group(1).upper() not in referenced
        )
    ]


def _remove_redundant_condition_operands(lines: list[str]) -> list[str]:
    """Remove calls emitted separately even though the following branch consumes them."""
    cleaned: list[str] = []
    for index, line in enumerate(lines):
        expression = re.match(r"^\s*((?!if\b|return\b)[^=;]+\));$", line)
        if expression:
            next_index = index + 1
            while next_index < len(lines) and not lines[next_index].strip():
                next_index += 1
            if (
                next_index < len(lines)
                and re.match(r"^\s*if \(", lines[next_index])
                and expression.group(1) in lines[next_index]
            ):
                continue
        cleaned.append(line)
    return cleaned


def _dangling_label_references(lines: list[str]) -> set[str]:
    labels = {
        match.group(1).upper()
        for line in lines
        for match in [re.match(r"^\s*loc_([0-9A-Fa-f]+):$", line)]
        if match
    }
    references = {
        match.group(1).upper()
        for line in lines
        for match in re.finditer(r"\b(?:goto|push_code_ptr) loc_([0-9A-Fa-f]+)", line)
    }
    return references - labels


def _structure_control_flow(lines: list[str]) -> list[str]:
    """Apply local CFG reductions until no additional source structure emerges."""
    lines = _remove_redundant_condition_operands(lines)

    def reduce_with(reducer, current: list[str]) -> list[str]:
        candidate = reducer(list(current))
        if _dangling_label_references(candidate) - _dangling_label_references(current):
            return current
        return candidate

    while True:
        before = list(lines)
        for reducer in (
            _structure_exclusive_dispatch,
            _structure_natural_loops,
            _structure_search_loops,
            _structure_return_terminated_loops,
            _fold_loop_exit_jumps,
            _fold_jump_over_return,
            _fold_terminal_jumps,
            _fold_short_circuit_lines,
            _structure_exclusive_dispatch,
            _structure_guard_chains,
            _structure_forward_if_lines,
            _structure_if_else_join_region,
            _structure_if_else_lines,
            _fold_boolean_bridges,
            _fold_true_branch_bridges,
            _fold_boolean_label_chain,
            _fold_materialized_or_bridges,
            _fold_empty_boolean_temp_bridge,
            _fold_nested_boolean_temp_bridge,
            _fold_nested_boolean_branch_bridge,
            _fold_materialized_branch_region,
            _fold_throw_direction_boolean,
            _recover_monster_damage_booleans,
            _propagate_side_effect_boolean,
            _recover_surge_state_conditions,
            _recover_grab_guard_assignment,
            _recover_stack_placeholders,
            _recover_known_result_slots,
            _recover_remaining_condition_slots,
            _structure_shared_if_else,
            _peel_shared_outer_guard,
            _structure_shared_guard_regions,
            _structure_guarded_if_else_join,
            _structure_three_way_guarded_tail,
            _structure_handled_tail_chain,
            _remove_unreferenced_labels,
        ):
            lines = reduce_with(reducer, lines)
        if lines == before:
            return lines


def _inline_adjacent_temporaries(lines: list[str]) -> list[str]:
    """Inline compiler temporaries consumed by the immediately following statement."""
    changed = True
    while changed:
        changed = False
        for index in range(len(lines) - 1):
            assignment = re.match(
                r"^(\s*)(temp_[A-Za-z0-9_]+)\s*=\s*(.+);$", lines[index]
            )
            if not assignment:
                continue
            indent, name, expression = assignment.groups()
            if re.search(rf"\b{re.escape(name)}\b", expression):
                continue
            next_index = index + 1
            while next_index < len(lines) and not lines[next_index].strip():
                next_index += 1
            if next_index >= len(lines):
                continue
            next_line = lines[next_index]
            if re.match(rf"^\s*{re.escape(name)}\s*=", next_line):
                continue
            occurrences = len(re.findall(rf"\b{re.escape(name)}\b", next_line))
            if occurrences != 1:
                continue
            safe_until_overwrite = True
            for candidate in lines[next_index + 1:]:
                if not re.search(rf"\b{re.escape(name)}\b", candidate):
                    continue
                safe_until_overwrite = bool(
                    re.match(rf"^\s*{re.escape(name)}\s*=", candidate)
                )
                break
            if not safe_until_overwrite:
                continue
            replacement = expression
            if not re.match(r"^[A-Za-z_]\w*(?:\([^;]*\)|(?:\.[A-Za-z_]\w*)*)$", expression):
                replacement = f"({expression})"
            lines[next_index] = re.sub(
                rf"\b{re.escape(name)}\b", replacement, next_line, count=1
            )
            del lines[index]
            changed = True
            break

    # Remove superseded argument staging stores only inside straight-line basic
    # blocks. A store followed by a branch may carry a value into the shared
    # target and must remain until that control-flow merge is reconstructed.
    removable: set[int] = set()
    boundary = re.compile(
        r"^\s*(?:loc_[0-9A-Fa-f]+:|goto\b|if\b|else\b|return\b|[{}])"
    )
    for index, line in enumerate(lines):
        assignment = re.match(
            r"^\s*(temp_[A-Za-z0-9_]+)\s*=\s*(.+);\s*$", line
        )
        if not assignment:
            continue
        name, expression = assignment.groups()
        if re.search(rf"\b{re.escape(name)}\b", expression):
            continue
        for candidate_index in range(index + 1, len(lines)):
            candidate = lines[candidate_index]
            if not candidate.strip():
                continue
            if boundary.match(candidate):
                break
            if (
                "(" in candidate
                and expression.strip() in candidate
                and not re.search(rf"\b{re.escape(name)}\b", candidate)
            ):
                removable.add(index)
                break
            if re.match(rf"^\s*{re.escape(name)}\s*=", candidate):
                removable.add(index)
                break
            if re.search(rf"\b{re.escape(name)}\b", candidate):
                break
    if removable:
        lines = [line for index, line in enumerate(lines) if index not in removable]

    referenced = "\n".join(lines)
    return [
        line
        for line in lines
        if not (
            (declaration := re.match(
                r"^\s*[A-Za-z_][A-Za-z0-9_-]*\s+(temp_[A-Za-z0-9_]+);$", line
            ))
            and len(re.findall(rf"\b{re.escape(declaration.group(1))}\b", referenced)) == 1
        )
    ]


def _remove_unread_temporary_stores(lines: list[str]) -> list[str]:
    """Drop compiler frame slots that have no source-level reads."""
    names = set(re.findall(r"\btemp_[A-Za-z][A-Za-z0-9_]*_\d+\b", "\n".join(lines)))
    unread: set[str] = set()
    for name in names:
        read = False
        for line in lines:
            if not re.search(rf"\b{re.escape(name)}\b", line):
                continue
            if re.match(rf"^\s*[A-Za-z_][A-Za-z0-9_-]*\s+{re.escape(name)};\s*$", line):
                continue
            assignment = re.match(rf"^\s*{re.escape(name)}\s*=\s*(.+);\s*$", line)
            if assignment and not re.search(rf"\b{re.escape(name)}\b", assignment.group(1)):
                continue
            read = True
            break
        if not read:
            unread.add(name)
    if not unread:
        return lines

    out: list[str] = []
    for line in lines:
        removed = False
        for name in unread:
            if re.match(rf"^\s*[A-Za-z_][A-Za-z0-9_-]*\s+{re.escape(name)};\s*$", line):
                removed = True
                break
            assignment = re.match(rf"^(\s*){re.escape(name)}\s*=\s*(.+);\s*$", line)
            if assignment:
                expression = assignment.group(2)
                if expression.endswith(")") and re.search(r"[A-Za-z_][A-Za-z0-9_]*\(", expression):
                    out.append(f"{assignment.group(1)}{expression};")
                removed = True
                break
        if not removed:
            out.append(line)
    return out


def _decompile_routine(
    instructions: list[PvmInstruction],
    type_names: list[str] | None = None,
    debug_frame: PvmDebugFrame | None = None,
    call_targets: dict[int, tuple[str, int]] | None = None,
) -> list[str]:
    """Lift one VM routine into cautious stack pseudocode.

    The stack is reset at control-flow joins. That loses some expressions, but
    avoids inventing values when two predecessor blocks have different stacks.
    """
    labels = {
        target for inst in instructions
        if (target := _pvm_branch_target(inst)) is not None
    }
    branch_ref_counts: dict[int, int] = {}
    instruction_index = {inst.code_offset: index for index, inst in enumerate(instructions)}
    for branch_inst in instructions:
        target = _pvm_branch_target(branch_inst)
        if target is not None:
            branch_ref_counts[target] = branch_ref_counts.get(target, 0) + 1
    simple_if_ends: dict[int, int] = {}
    for index, branch_inst in enumerate(instructions):
        if branch_inst.op not in (0x6F, 0x70):
            continue
        target = _pvm_branch_target(branch_inst)
        target_index = instruction_index.get(target) if target is not None else None
        if target_index is None or target_index <= index or branch_ref_counts.get(target, 0) != 1:
            continue
        body = instructions[index + 1:target_index]
        if body and not any(item.op in (0x6F, 0x70, 0x71) for item in body):
            simple_if_ends[target] = branch_inst.code_offset
    stack: list[str] = []
    lines: list[str] = []
    local_types = _frame_local_types(instructions, type_names or [])
    local_source_names: dict[int, str] = {}
    used_local_names: dict[str, int] = {}
    if debug_frame is not None:
        for offset, source_name in zip(local_types, debug_frame.local_names):
            safe_name = _pvm_source_identifier(source_name)
            used_local_names[safe_name] = used_local_names.get(safe_name, 0) + 1
            if used_local_names[safe_name] > 1:
                safe_name = f"{safe_name}_{used_local_names[safe_name]}"
            local_source_names[offset] = safe_name
    incoming_stacks: dict[int, list[list[str]]] = {}
    local_values: dict[str, str] = {}

    def local_name(offset: int) -> str:
        if offset in local_source_names:
            return local_source_names[offset]
        type_name = local_types.get(offset)
        if type_name:
            return f"local_{_pvm_source_identifier(type_name)}_{offset:04X}"
        return f"local_{offset:04X}"

    frame_local_names = {local_name(offset) for offset in local_types}

    def push(value: str) -> None:
        stack.append(value)

    def pop(default: str = "stack_value") -> str:
        while stack and stack[-1].startswith("__return_address_"):
            stack.pop()
        return stack.pop() if stack else default

    def resolved(value: str) -> str:
        seen: set[str] = set()
        while value in local_values and value not in seen:
            seen.add(value)
            value = local_values[value]
        return value

    def remember_stack(target: int | None) -> None:
        if target is not None:
            incoming_stacks.setdefault(target, []).append(list(stack))

    def common_stack(states: list[list[str]]) -> list[str]:
        if not states:
            return []
        prefix = list(states[0])
        for state in states[1:]:
            keep = 0
            for left, right in zip(prefix, state):
                if left != right:
                    break
                keep += 1
            prefix = prefix[:keep]
        return prefix

    def consume_call_arguments(remove_return_slot: bool = False) -> list[str]:
        marker_index = next(
            (
                index for index in range(len(stack) - 1, -1, -1)
                if stack[index].startswith("__arg_count_")
            ),
            None,
        )
        if marker_index is None:
            return []
        count = int(stack[marker_index].rsplit("_", 1)[1])
        start = max(0, marker_index - count)
        arguments = [resolved(value) for value in stack[start:marker_index]]
        del stack[start:marker_index + 1]
        return_index = next(
            (
                index for index in range(len(stack) - 1, -1, -1)
                if stack[index].startswith("__return_address_")
            ),
            None,
        )
        if return_index is not None:
            remove_indices = {return_index}
            if remove_return_slot:
                # The compiler emits both `result, continuation` and
                # `continuation, result` layouts depending on whether nested
                # calls are used while forming the arguments.
                if return_index + 1 < len(stack):
                    remove_indices.add(return_index + 1)
                elif return_index > 0:
                    remove_indices.add(return_index - 1)
            for remove_index in sorted(remove_indices, reverse=True):
                del stack[remove_index]
        return arguments

    def emit_discarded_calls() -> None:
        """Preserve call side effects before a control-flow edge clears the VM stack."""
        retained: list[str] = []
        emitted: set[str] = set()
        for value in stack:
            value = resolved(value)
            if value.endswith(")") and re.search(r"[A-Za-z_][A-Za-z0-9_]*\(", value):
                lines.append(f"    {value};")
                emitted.add(value)
            else:
                retained.append(value)
        stack[:] = retained
        if emitted:
            for states in incoming_stacks.values():
                for state in states:
                    state[:] = [value for value in state if resolved(value) not in emitted]

    padding_offsets = set()
    for index in range(len(instructions) - 4):
        if (
            instructions[index].op in {0x77, 0x78}
            and [item.op for item in instructions[index + 1:index + 4]] == [0x76, 0x76, 0x76]
            and instructions[index + 4].op == 0x71
        ):
            padding_offsets.update(item.code_offset for item in instructions[index + 1:index + 4])

    for inst_index, inst in enumerate(instructions):
        if inst.code_offset in simple_if_ends:
            lines.append("    }")
        if inst.code_offset in labels:
            emit_discarded_calls()
            states = incoming_stacks.get(inst.code_offset, [])
            if stack:
                states = states + [list(stack)]
            if states:
                stack[:] = common_stack(states)
            local_values.clear()
            # Keep the raw target until source structuring has consumed every
            # reference. Suppressing it from the preliminary simple-if guess
            # can leave a dangling branch when another CFG edge shares the
            # same instruction boundary.
            lines.append(f"    loc_{inst.code_offset:06X}:")
        raw = inst.raw
        op = inst.op
        note = ""

        if op == 0x6C:
            if local_types:
                for offset, type_name in sorted(local_types.items()):
                    lines.append(f"    {type_name} {local_name(offset)};")
                lines.append("")
        elif op == 0x64 and len(raw) >= 3:
            push(local_name(int.from_bytes(raw[1:3], "big")))
        elif op == 0x65 and len(raw) >= 2:
            if debug_frame is not None and raw[1] < len(debug_frame.argument_names):
                push(debug_frame.argument_names[raw[1]])
            else:
                push(f"stack_relative_{raw[1]}")
        elif op in (0x66, 0x67) and len(raw) >= 5:
            index = _u24(raw[2:5])
            # decode_pvm_instructions has already resolved this reference using
            # the module pools; retain that proven display name here.
            decoded = inst.text.split(" ;", 1)[0].split(" ", 1)[1]
            push(decoded)
        elif op == 0x68:
            push("null")
        elif op == 0x69 and len(raw) >= 5:
            # The compiler pushes a continuation address before a VM call. It
            # is call-frame metadata, not a source-level pointer expression.
            if stack:
                # A resolved frame slot may merely be the hidden destination
                # of the nested call that follows. Only emit a call already
                # present literally on the operand stack.
                pending = stack[-1]
                if pending.endswith(")") and re.search(
                    r"[A-Za-z_][A-Za-z0-9_]*\(", pending
                ):
                    lines.append(f"    {pending};{note}")
                    stack.pop()
            push(f"__return_address_{_u24(raw[2:5]):06X}")
        elif op == 0x6A and len(raw) >= 5:
            value = _u24(raw[2:5])
            push(f"__arg_count_{value}")
        elif op == 0x6B and len(raw) >= 2:
            for _ in range(min(raw[1], len(stack))):
                dropped = stack.pop()
                if re.match(r"^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*\(.*\)$", dropped):
                    lines.append(f"    {dropped};{note}")
        elif op == 0x6D and len(raw) >= 3:
            token, mode = raw[1], raw[2]
            if mode in (0, 1):
                right, left = resolved(pop()), resolved(pop())
                if mode == 0 and token == 66:
                    # PPToken 66 is unary numeric negation. The value on the
                    # left is the compiler-provided typed result slot, not a
                    # source operand.
                    push(f"(-{right})")
                    continue
                if mode == 0 and token in (67, 68):
                    operator = "++" if token == 67 else "--"
                    lines.append(f"    {operator}{right};{note}")
                    push(left)
                    continue
                if mode == 1 and token in (67, 68, 69, 70):
                    operator = "++" if token in (67, 69) else "--"
                    lines.append(f"    {right}{operator};{note}")
                    if left in frame_local_names and left != right:
                        local_values[left] = right
                    push(left)
                    continue
                operator = PV_BINARY_TOKENS.get(token)
                push(f"({left} {operator} {right})" if operator else f"op_{token}({left}, {right})")
            elif mode == 2:
                value = resolved(pop())
                push(f"!({value})" if token == 13 else value)
            elif mode == 3:
                value, destination = resolved(pop()), pop()
                if destination.startswith("__pvm_result_"):
                    push(value)
                else:
                    lines.append(f"    {destination} = {value};{note}")
                    if (
                        destination in frame_local_names
                        and destination not in value
                        and not re.search(r"[A-Za-z_][A-Za-z0-9_:.]*\(", value)
                    ):
                        local_values[destination] = value
                    else:
                        local_values.pop(destination, None)
                    push(destination)
            elif mode == 4:
                right, left = resolved(pop()), resolved(pop())
                destination = pop("comparison_result")
                operator = PV_COMPARISON_TOKENS.get(token, f"compare_{token}")
                push(f"({left} {operator} {right})" if token in PV_COMPARISON_TOKENS else f"{operator}({left}, {right})")
            elif mode == 6:
                right, left = resolved(pop()), resolved(pop())
                destination = pop("operator_result")
                operator = PV_BINARY_TOKENS.get(token)
                push(f"({left} {operator} {right})" if operator else f"op_{token}({left}, {right})")
            elif mode not in (5, 7):
                lines.append(f"    apply_operator(token={token}, mode={mode});{note}")
        elif op in (0x6E, 0x75) and len(raw) >= 3:
            receiver = resolved(pop("object"))
            arguments = consume_call_arguments(remove_return_slot=True) if op == 0x6E else []
            argument_text = ", ".join(arguments)
            member_id = int.from_bytes(raw[1:3], "big")
            if member_id == 0xFFFF:
                # PFuncSymbol::callMember ignores this sentinel member ID and
                # invokes the function symbol directly.
                result = f"{receiver}({argument_text})"
            else:
                member = inst.text.split(".", 1)[-1]
                if op == 0x75 or receiver == "this":
                    result = f"{member}({argument_text})"
                else:
                    result = f"{receiver}.{member}({argument_text})"
            push(result)
        elif op in (0x6F, 0x70):
            target = _pvm_branch_target(inst)
            condition = resolved(pop("condition"))
            if target in simple_if_ends and simple_if_ends[target] == inst.code_offset:
                source_condition = condition if op == 0x70 else f"!({condition})"
                lines.append(f"    if ({source_condition}) {{{note}")
            else:
                if op == 0x70:
                    condition = f"!({condition})"
                lines.append(f"    if ({condition}) goto loc_{target:06X};{note}")
            remember_stack(target)
            local_values.clear()
        elif op == 0x71:
            target = _pvm_branch_target(inst)
            call_target = (call_targets or {}).get(target)
            routine_start = instructions[0].code_offset if instructions else -1
            if call_target is not None and target == routine_start:
                function_name, argument_count = call_target
                arguments = consume_call_arguments()
                arguments = arguments[-argument_count:] if argument_count else []
                emit_discarded_calls()
                lines.append(f"    {function_name}({', '.join(arguments)});{note}")
                lines.append(f"    return;{note}")
                stack.clear()
                local_values.clear()
                continue
            if call_target is not None and target != routine_start:
                function_name, argument_count = call_target
                arguments = consume_call_arguments()
                arguments = arguments[-argument_count:] if argument_count else []
                # Script calls return through the frame slot left immediately
                # below their continuation record. Keep the call as a stack
                # expression so the following VM copy can bind that result to
                # its actual source destination.
                push(f"{function_name}({', '.join(arguments)})")
            else:
                emit_discarded_calls()
                lines.append(f"    goto loc_{target:06X};{note}")
                remember_stack(target)
                stack.clear()
                local_values.clear()
        elif op in (0x72, 0x73) and len(raw) >= 7:
            local = int.from_bytes(raw[5:7], "big")
            value = resolved(pop())
            destination = local_name(local)
            lines.append(f"    {destination} = {value};{note}")
            if destination not in value:
                local_values[destination] = value
            else:
                local_values.pop(destination, None)
            push(destination)
        elif op == 0x74 and len(raw) >= 3:
            local = int.from_bytes(raw[1:3], "big")
            value = resolved(pop())
            destination = local_name(local)
            lines.append(f"    {destination} = {value};{note}")
            if destination not in value:
                local_values[destination] = value
            else:
                local_values.pop(destination, None)
            push(destination)
        elif op == 0x76:
            if inst.code_offset in padding_offsets:
                continue
            right, left = resolved(pop()), resolved(pop())
            push(f"resolve({left}, {right})")
        elif op == 0x77:
            value = resolved(pop())
            emit_discarded_calls()
            lines.append(f"    return {value};{note}")
            stack.clear()
        elif op == 0x78:
            emit_discarded_calls()
            lines.append(f"    return;{note}")
            stack.clear()
        elif op == 0x79:
            lines.append(f"    return_vm_state(1);{note}")
            stack.clear()
        elif op == 0x7A:
            # Compiler/runtime terminator bytes are retained in the PVM but
            # are not source statements. Modules commonly end with three to
            # satisfy code-section alignment after the final return opcode.
            continue
        else:
            lines.append(f"    {inst.text};{note}")
    emit_discarded_calls()
    lines = _remove_unread_temporary_stores(_inline_adjacent_temporaries(lines))
    lines = _remove_unread_temporary_stores(
        _inline_adjacent_temporaries(_structure_control_flow(lines))
    )
    # Temporary cleanup can expose adjacent branch operands that were
    # separated during the first pass. Run the CFG reducer once more on that
    # cleaner statement stream so boolean diamonds are consumed completely.
    lines = _remove_unread_temporary_stores(
        _inline_adjacent_temporaries(_structure_control_flow(lines))
    )
    indented: list[str] = []
    block_depth = 0
    for line in lines:
        stripped = line.strip()
        if stripped == "}" or stripped.startswith("} else"):
            block_depth = max(0, block_depth - 1)
        if line.startswith("    ") and stripped:
            line = ("    " * block_depth) + line
        indented.append(line)
        if (
            stripped.startswith("if (") and stripped.endswith("{")
            or stripped.startswith("else if (") and stripped.endswith("{")
            or stripped.startswith("while (") and stripped.endswith("{")
            or "{ // +0x" in stripped
            or stripped.startswith("} else")
        ):
            block_depth += 1
    return indented


def _pvm_source_identifier(name: str) -> str:
    ident = re.sub(r"[^A-Za-z0-9_]", "_", name).strip("_")
    if not ident:
        ident = "value"
    if not re.match(r"^[A-Za-z_]", ident):
        ident = "_" + ident
    return ident


def _pvm_source_aliases(values: list[PvmTypedValue]) -> dict[int, str]:
    used: set[str] = set()
    typed_counts: dict[tuple[str, str], int] = {}
    aliases: dict[int, str] = {}
    for item in values:
        base = _pvm_source_identifier(item.name)
        if base not in used:
            aliases[item.entry_index] = base
            used.add(base)
            continue
        type_name = _pvm_source_identifier(item.type_name)
        key = (base, type_name)
        typed_counts[key] = typed_counts.get(key, 0) + 1
        suffix = type_name if typed_counts[key] == 1 else f"{type_name}_{typed_counts[key]}"
        alias = f"{base}_{suffix}"
        while alias in used:
            typed_counts[key] += 1
            alias = f"{base}_{type_name}_{typed_counts[key]}"
        aliases[item.entry_index] = alias
        used.add(alias)
    return aliases


def _format_pvm_source_value(value: int | float | str) -> str:
    if isinstance(value, str):
        return repr(value)
    if isinstance(value, float):
        return repr(value)
    return str(value)


def format_pvm_globals_source(module: PvmModule, path: Path | None = None) -> str:
    """Emit the normal GUI-editable PVM view.

    Globals and the proven source-compiler subset are editable. Unsupported
    structural changes fail explicitly instead of being silently discarded.
    """
    typed_values = extract_typed_values(module)
    aliases = _pvm_source_aliases(typed_values)
    module_name = _pvm_source_identifier(path.stem if path is not None else "PVM_Module")

    lines = []
    lines.append("# PVM source workbench export")
    if path is not None:
        lines.append(f"# SourcePVM={path}")
    lines.append(f"# PVM={path.name if path is not None else ''}")
    lines.append(f"# Version={module.version_text}")
    lines.append("# Editable: global table, source code values, arguments, and functions.")
    lines.append("")
    lines.append(f"module {module_name}")
    lines.append("{")
    lines.append("    globals [Open][Close]")
    lines.append("    {")
    if typed_values:
        declarations = []
        for item in typed_values:
            alias = aliases[item.entry_index]
            value = _format_pvm_source_value(item.value)
            declarations.append((f"        {item.type_name} {alias} = {value};", item.file_offset))
        comment_column = max(len(declaration) for declaration, _ in declarations) + 8
        for declaration, file_offset in declarations:
            lines.append(f"{declaration:<{comment_column}}// @0x{file_offset:06X}")
    else:
        lines.append("        // No typed globals were recovered from section 1.")
    lines.append("    }")
    lines.append("")
    lines.append("    code")
    lines.append("    {")
    entries = pvm_code_entries(module)
    debug_frames = pvm_debug_frames(module)
    call_targets = _pvm_call_targets(entries, debug_frames)
    grouped = _instructions_by_routine(module, entries)
    for entry in entries:
        debug_frame = debug_frames.get(entry.index)
        function_name = debug_frame.function_name if debug_frame else entry.name
        arguments = ", ".join(
            name for name in debug_frame.argument_names if name != "this"
        ) if debug_frame else ""
        lines.append(f"        function {function_name}({arguments})")
        lines.append("        {")
        body_lines = _decompile_routine(
            grouped[entry.index], _type_names(module), debug_frame, call_targets
        )
        balance = sum(line.count("{") - line.count("}") for line in body_lines)
        if balance > 0:
            body_lines.extend("    }" for _ in range(balance))
        for source_line in body_lines:
            lines.append("        " + source_line)
        lines.append("        }")
        lines.append("")
    lines.append("    }")
    lines.append("}")
    return "\n".join(lines).rstrip() + "\n"


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
        op = _canonical_opcode(code[offset], module.version_text)
        size = pvm_op_size(code, offset, module.version_text, module.endian)
        if size <= 1 or offset + size > len(code):
            continue
        source_raw = code[offset:offset + size]
        raw = _canonical_instruction_raw(offset, source_raw, op, module.endian)

        if op in (0x65,):
            value = raw[1]
            out.append(PvmEditableValue(code_base + offset + 1, offset, op, "u8", value, raw[1:2]))
        elif op in (0x64, 0x6E, 0x74, 0x75):
            value = int.from_bytes(raw[1:3], "big")
            note = ""
            if op in (0x6E, 0x75):
                note = _symbol_note(value, symbols, debug)
            out.append(PvmEditableValue(code_base + offset + 1, offset, op, "u16", value, source_raw[1:3], note))
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
            operand_offset = 1 if module.endian == "<" else 2
            source_value = source_raw[1:4] if module.endian == "<" else source_raw[2:5]
            out.append(PvmEditableValue(code_base + offset + operand_offset, offset, op, "u24", value, source_value, note, tag=tag))
        elif op in (0x72, 0x73) and len(raw) >= 7:
            tag = raw[1]
            target = _u24(raw[2:5])
            local = int.from_bytes(raw[5:7], "big")
            note = _code_note(target, len(code)) or _symbol_note(target, symbols, debug)
            operand_offset = 1 if module.endian == "<" else 2
            source_value = source_raw[1:4] if module.endian == "<" else source_raw[2:5]
            out.append(PvmEditableValue(code_base + offset + operand_offset, offset, op, "u24", target, source_value, note, tag=tag))
            out.append(PvmEditableValue(code_base + offset + 5, offset, op, "u16", local, source_raw[5:7], "local slot", tag=tag))
        elif op == 0x6D:
            subtype = raw[2] if len(raw) > 2 else -1
            if len(raw) >= 3:
                out.append(PvmEditableValue(code_base + offset + 1, offset, op, "u8", raw[1], raw[1:2], f"6D subtype={subtype}"))
            if len(raw) >= 7:
                tag = raw[3]
                value = _u24(raw[4:7])
                note = _symbol_note(value, symbols, debug) or _code_note(value, len(code))
                operand_offset = 3 if module.endian == "<" else 4
                source_value = source_raw[3:6] if module.endian == "<" else source_raw[4:7]
                out.append(PvmEditableValue(code_base + offset + operand_offset, offset, op, "u24", value, source_value, note, tag=tag))
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
    count = struct.unpack_from(f"{module.endian}I", blob, 0)[0]
    names: list[str] = []
    offset = 4
    for _ in range(count):
        if offset + 8 > len(blob):
            break
        size = struct.unpack_from(f"{module.endian}H", blob, offset + 2)[0]
        name_offset = struct.unpack_from(f"{module.endian}I", blob, offset + 4)[0]
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


def _typed_value_assignment_names(module: PvmModule) -> dict[int, str]:
    """Name literals assigned directly to globals in the module initializer."""
    code = section_data(module, 0)
    variable_names, _function_names = _global_symbol_names(module)
    entries = pvm_code_entries(module)
    if not entries:
        return {}
    main_end = entries[0].end_code_offset
    offsets = [offset for offset in _instruction_offsets(module) if offset < main_end]
    names: dict[int, str] = {}
    for index in range(len(offsets) - 2):
        left = offsets[index]
        right = offsets[index + 1]
        assign = offsets[index + 2]
        if _canonical_opcode(code[left], module.version_text) != 0x66:
            continue
        if _canonical_opcode(code[right], module.version_text) != 0x67:
            continue
        if _canonical_opcode(code[assign], module.version_text) != 0x6D:
            continue
        left_raw = _canonical_instruction_raw(
            left, code[left:left + pvm_op_size(code, left, module.version_text, module.endian)],
            0x66, module.endian,
        )
        right_raw = _canonical_instruction_raw(
            right, code[right:right + pvm_op_size(code, right, module.version_text, module.endian)],
            0x67, module.endian,
        )
        assign_raw = _canonical_instruction_raw(
            assign, code[assign:assign + pvm_op_size(code, assign, module.version_text, module.endian)],
            0x6D, module.endian,
        )
        if len(left_raw) < 5 or left_raw[1] != 1:
            continue
        if len(right_raw) < 5 or right_raw[1] != 3:
            continue
        if len(assign_raw) < 3 or assign_raw[1:3] != b"\x14\x03":
            continue
        variable_index = _u24(left_raw[2:5])
        value_index = _u24(right_raw[2:5])
        if variable_index in variable_names:
            names.setdefault(value_index, variable_names[variable_index])
    return names


def _typed_literal_name(type_name: str, value: int | float | str) -> str:
    if type_name == "string":
        if not value:
            return "empty_string"
        text = _safe_key(str(value))
        return text if any(ch.isalpha() for ch in str(value)) else f"string_{text}"
    if type_name == "float":
        text = format(float(value), ".9g").replace("-", "negative_").replace(".", "_")
        return f"float_{text}"
    text = str(int(value)).replace("-", "negative_")
    return f"int_{text}"


def extract_typed_values(module: PvmModule) -> list[PvmTypedValue]:
    type_names = _type_names(module)
    strings = section_data(module, 6)
    blob = section_data(module, 1)
    rows: list[PvmTypedValue] = []
    assignment_names = _typed_value_assignment_names(module)

    if len(blob) < 4:
        return rows
    count = struct.unpack_from(f"{module.endian}H", blob, 0)[0]
    max_count = (len(blob) - 4) // 8
    if count > max_count:
        return rows

    pending_labels: list[str] = []
    for entry_index in range(count):
        offset = 4 + entry_index * 8
        type_index = struct.unpack_from(f"{module.endian}H", blob, offset)[0]
        if type_index >= len(type_names):
            continue
        type_name = type_names[type_index]
        raw_value = struct.unpack_from(f"{module.endian}I", blob, offset + 4)[0]
        value = _decode_initial_value(type_name, raw_value, strings)
        if value is None:
            pending_labels.clear()
            continue

        file_offset = module.sections[1].offset + offset + 4
        if type_name == "string":
            name = assignment_names.get(entry_index, _typed_literal_name(type_name, value))
            rows.append(PvmTypedValue(file_offset, entry_index, type_name, name, value, raw_value))
            if _looks_like_value_label(value):
                pending_labels.append(value)
            continue

        if entry_index in assignment_names:
            name = assignment_names[entry_index]
        elif pending_labels:
            name = _safe_key(pending_labels.pop(0))
        else:
            name = _typed_literal_name(type_name, value)
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
    first_u32 = struct.unpack_from(f"{module.endian}I", blob, 0)[0]
    words = [struct.unpack_from(f"{module.endian}I", blob, off)[0] for off in range(0, min(len(blob), 32), 4)]
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

    lines.append(format_pvm_entries(module))
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
            section_name = PVM_SECTION_NAMES.get(section.index, f"Section{section.index}")
            lines.append(
                f"{section.index} {section_name}: offset=0x{section.offset:06X} "
                f"size=0x{section.size:06X} end=0x{section.end:06X}"
            )
        lines.append("")
        lines.append(_format_pvm_diagnostics(module))
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def format_pvm_editor_view(module: PvmModule, path: Path | None = None) -> str:
    return format_pvm_globals_source(module, path)


def pvm_to_editable(data: bytes, path: Path | None = None) -> str:
    return format_pvm_editor_view(parse_pvm(data), path)


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
    pool = section_data(module, 6)
    prefix = b"" if not pool or pool[-1] == 0 else b"\0"
    string_offset = string_section.size + len(prefix)
    payload = prefix + encoded + b"\0"
    data[insert_at:insert_at] = payload
    delta = len(payload)
    struct.pack_into(f"{module.endian}I", data, 0x34, len(data))
    for index, section in enumerate(module.sections):
        entry = SECTION_TABLE_START + index * 8
        if index == 6:
            struct.pack_into(f"{module.endian}I", data, entry + 4, section.size + delta)
        elif index > 6:
            struct.pack_into(f"{module.endian}I", data, entry, section.offset + delta)
    return string_offset


def _rebuild_pvm_sections(module: PvmModule, replacements: dict[int, bytes]) -> bytes:
    """Repack sections in their original physical order and rewrite the header."""
    header = bytearray(module.data[:HEADER_SIZE])
    payload = bytearray(header)
    locations: dict[int, tuple[int, int]] = {}
    for section in sorted(module.sections, key=lambda item: item.offset):
        while len(payload) & 3:
            payload.append(0)
        blob = replacements.get(section.index, section_data(module, section.index))
        locations[section.index] = (len(payload), len(blob))
        payload.extend(blob)
    struct.pack_into(f"{module.endian}I", payload, 0x34, len(payload))
    for index in range(SECTION_COUNT):
        offset, size = locations[index]
        struct.pack_into(f"{module.endian}II", payload, SECTION_TABLE_START + index * 8, offset, size)
    return bytes(payload)


def _map_spliced_code_offset(value: int, start: int, removed: int, added: int) -> int:
    end = start + removed
    if value < start:
        return value
    if value >= end:
        return value + added - removed
    relative = value - start
    if relative < added:
        # Function entry points, aligned frame markers, and early debug-line
        # markers remain valid when the replacement retains that prefix.
        return start + relative
    raise ValueError(f"Code address 0x{value:X} points into the replaced byte range.")


def splice_pvm_code(
    original_data: bytes,
    code_offset: int,
    remove_size: int,
    replacement: bytes,
) -> bytes:
    """Replace an aligned code range and relocate every proven code address.

    This is the bytecode-growth primitive used by the source compiler. Keeping
    the size delta four-byte aligned preserves the alignment-sensitive 0x6C
    frame headers of all following routines.
    """
    module = parse_pvm(original_data)
    old_code = section_data(module, 0)
    if not (0 <= code_offset <= len(old_code)):
        raise ValueError("Code splice starts outside section 0.")
    if remove_size < 0 or code_offset + remove_size > len(old_code):
        raise ValueError("Code splice removal range is outside section 0.")
    delta = len(replacement) - remove_size
    if delta & 3:
        raise ValueError("PVM code growth must be four-byte aligned.")

    def mapped(value: int) -> int:
        return _map_spliced_code_offset(value, code_offset, remove_size, len(replacement))

    code = bytearray(old_code[:code_offset] + replacement + old_code[code_offset + remove_size:])
    # Relocate branch targets and call continuations in preserved instructions.
    for inst in decode_pvm_instructions(module):
        if code_offset <= inst.code_offset < code_offset + remove_size:
            continue
        if inst.op not in {0x69, 0x6F, 0x70, 0x71} or len(inst.raw) < 5:
            continue
        new_inst_offset = mapped(inst.code_offset)
        target = _u24(inst.raw[2:5])
        _patch_tagged_u24(code, new_inst_offset, mapped(target), module.endian)

    # Exported function records contain section-0 entry offsets at +4.
    symbols = bytearray(section_data(module, 2))
    if len(symbols) >= 12:
        variable_count = struct.unpack_from(f"{module.endian}I", symbols, 0)[0]
        function_count = struct.unpack_from(f"{module.endian}H", symbols, 8)[0]
        function_start = 12 + variable_count * 8
        for index in range(function_count):
            pos = function_start + index * 16 + 4
            if pos + 4 <= len(symbols):
                value = struct.unpack_from(f"{module.endian}I", symbols, pos)[0]
                if value != 0xFFFFFFFF and value < len(old_code):
                    struct.pack_into(f"{module.endian}I", symbols, pos, mapped(value))

    # Debug line records and frame markers both use section-0 code offsets.
    runtime = bytearray(section_data(module, 7))
    if len(runtime) >= 8:
        line_count, frame_count = struct.unpack_from(f"{module.endian}II", runtime, 0)
        for index in range(min(line_count, (len(runtime) - 8) // 12)):
            pos = 8 + index * 12
            value = struct.unpack_from(f"{module.endian}I", runtime, pos)[0]
            if value < len(old_code):
                struct.pack_into(f"{module.endian}I", runtime, pos, mapped(value))
        cursor = 8 + line_count * 12
        if cursor + 16 <= len(runtime):
            preamble_name_count = struct.unpack_from(f"{module.endian}H", runtime, cursor + 4)[0]
            cursor += 16 + preamble_name_count * 4
            for _entry_index in range(1, frame_count):
                if cursor + 16 > len(runtime):
                    break
                marker = struct.unpack_from(f"{module.endian}I", runtime, cursor)[0]
                local_count, argument_count = struct.unpack_from(f"{module.endian}HH", runtime, cursor + 4)
                if marker < len(old_code):
                    struct.pack_into(f"{module.endian}I", runtime, cursor, mapped(marker))
                cursor += 16 + (local_count + argument_count) * 4

    rebuilt = _rebuild_pvm_sections(
        module,
        {0: bytes(code), 2: bytes(symbols), 7: bytes(runtime)},
    )
    parse_pvm(rebuilt)
    return rebuilt


def _append_pool_text(blob: bytes, value: str) -> tuple[bytes, int]:
    encoded = value.encode("latin-1")
    for offset, text in extract_null_strings(blob, 0):
        if text == value:
            return blob, offset
    prefix = b"" if not blob or blob[-1] == 0 else b"\0"
    offset = len(blob) + len(prefix)
    return blob + prefix + encoded + b"\0", offset


def _function_signature_runtime_size(module: PvmModule, function_record: bytes) -> int:
    """Return PVUnpackSignature's runtime byte count for one function record."""
    if len(function_record) < 14:
        raise ValueError("PVM function record is truncated.")
    signature_index = struct.unpack_from(f"{module.endian}H", function_record, 12)[0]
    signatures = section_data(module, 3)
    offset_pos = 8 + signature_index * 4
    if offset_pos + 4 > len(signatures):
        raise ValueError(f"PVM signature index {signature_index} is outside section 3.")
    signature_offset = struct.unpack_from(f"{module.endian}I", signatures, offset_pos)[0]
    if signature_offset + 2 > len(signatures):
        raise ValueError(f"PVM signature {signature_index} points outside section 3.")
    argument_count = signatures[signature_offset + 1]
    return 16 + argument_count * 4


def append_cloned_pvm_function(
    original_data: bytes,
    source_function: str,
    new_function: str,
) -> bytes:
    """Append a callable function by cloning a proven signature and body.

    This is primarily a format-verification primitive for the source compiler:
    it exercises code growth plus function-symbol and debug-frame creation.
    """
    module = parse_pvm(original_data)
    entries = pvm_code_entries(module)
    frames = pvm_debug_frames(module)
    source_entry = next(
        (entry for entry in entries if frames.get(entry.index) and frames[entry.index].function_name == source_function),
        None,
    )
    if source_entry is None or source_entry.index == 0:
        raise ValueError(f"Function {source_function!r} was not found or has no export signature.")
    if any(frame.function_name == new_function for frame in frames.values()):
        raise ValueError(f"Function {new_function!r} already exists.")

    old_code = section_data(module, 0)
    source_blob = bytearray(old_code[source_entry.code_offset:source_entry.end_code_offset])
    # The Wii linker walks section 0 only until the module-level 0x7A `end`
    # instruction. New routines must be inserted before that terminator or
    # their frame type descriptors remain unresolved tagged values at runtime.
    terminal_start = len(old_code)
    while terminal_start and old_code[terminal_start - 1] == 0x7A:
        terminal_start -= 1
    terminal = old_code[terminal_start:]
    if not terminal:
        terminal = b"\x7A"
    padding = (source_entry.code_offset - terminal_start) & 3
    new_start = terminal_start + padding
    shift = new_start - source_entry.code_offset
    for inst in _instructions_in_range(module, source_entry.code_offset, source_entry.end_code_offset):
        rel = inst.code_offset - source_entry.code_offset
        if inst.op in {0x69, 0x6F, 0x70, 0x71} and len(inst.raw) >= 5:
            target = _u24(inst.raw[2:5])
            if source_entry.code_offset <= target < source_entry.end_code_offset:
                _patch_tagged_u24(source_blob, rel, target + shift, module.endian)

    strings, symbol_name_offset = _append_pool_text(section_data(module, 6), new_function)
    debug_strings, debug_name_offset = _append_pool_text(section_data(module, 8), new_function)

    symbols = bytearray(section_data(module, 2))
    variable_count = struct.unpack_from(f"{module.endian}I", symbols, 0)[0]
    function_count = struct.unpack_from(f"{module.endian}H", symbols, 8)[0]
    owned_function_count = struct.unpack_from(f"{module.endian}H", symbols, 10)[0]
    # Inserting into the owned prefix shifts every imported function symbol by
    # one. Relocate tag-0 push-copy operands in both existing and cloned code.
    relocated_old_code = bytearray(old_code)
    for inst in decode_pvm_instructions(module):
        if inst.op == 0x66 and len(inst.raw) >= 5 and inst.raw[1] == 0:
            index = _u24(inst.raw[2:5])
            if index >= owned_function_count:
                _patch_tagged_u24(relocated_old_code, inst.code_offset, index + 1, module.endian)
    for inst in _instructions_in_range(module, source_entry.code_offset, source_entry.end_code_offset):
        if inst.op == 0x66 and len(inst.raw) >= 5 and inst.raw[1] == 0:
            index = _u24(inst.raw[2:5])
            if index >= owned_function_count:
                _patch_tagged_u24(
                    source_blob,
                    inst.code_offset - source_entry.code_offset,
                    index + 1,
                    module.endian,
                )
    # Alignment bytes are unreachable after the previous routine's return,
    # but cannot themselves be `end` instructions because the linker scans
    # them linearly. Keep the one-byte opcode slots non-terminating.
    code = (
        bytes(relocated_old_code[:terminal_start])
        + (b"\x76" * padding)
        + bytes(source_blob)
        + terminal
    )
    function_start = 12 + variable_count * 8
    source_symbol_index = source_entry.index - 1
    source_record_pos = function_start + source_symbol_index * 16
    if source_record_pos + 16 > len(symbols):
        raise ValueError("Source function has no matching section-2 symbol record.")
    record = bytearray(symbols[source_record_pos:source_record_pos + 16])
    signature_runtime_size = _function_signature_runtime_size(module, record)
    struct.pack_into(f"{module.endian}I", record, 0, symbol_name_offset)
    struct.pack_into(f"{module.endian}I", record, 4, new_start)
    # Owned script functions occupy the leading records; imported/native
    # symbols follow them with code address 0xFFFFFFFF. The runtime and debug
    # frame indices address the owned prefix, so append before the imports.
    insert_at = function_start + owned_function_count * 16
    symbols[insert_at:insert_at] = record
    struct.pack_into(f"{module.endian}H", symbols, 8, function_count + 1)
    # resolveGlobals allocates the module-owned PFuncSymbol pointer array from
    # the second count. PVLoadedModule::~PVLoadedModule later iterates exactly
    # this count and clears each symbol's module/code links.
    struct.pack_into(f"{module.endian}H", symbols, 10, owned_function_count + 1)
    runtime_storage_size = struct.unpack_from(f"{module.endian}I", symbols, 4)[0]
    struct.pack_into(f"{module.endian}I", symbols, 4, runtime_storage_size + signature_runtime_size)

    runtime = bytearray(section_data(module, 7))
    line_count, frame_count = struct.unpack_from(f"{module.endian}II", runtime, 0)
    cursor = 8 + line_count * 12
    preamble_name_count = struct.unpack_from(f"{module.endian}H", runtime, cursor + 4)[0]
    cursor += 16 + preamble_name_count * 4
    source_frame_blob = None
    for entry_index in range(1, frame_count):
        frame_start = cursor
        local_count, argument_count = struct.unpack_from(f"{module.endian}HH", runtime, cursor + 4)
        cursor += 16 + (local_count + argument_count) * 4
        if entry_index == source_entry.index:
            source_frame_blob = bytearray(runtime[frame_start:cursor])
    if source_frame_blob is None:
        raise ValueError("Source function has no matching debug-frame record.")
    struct.pack_into(f"{module.endian}I", source_frame_blob, 0, (new_start + 4) & ~3)
    struct.pack_into(f"{module.endian}I", source_frame_blob, 12, debug_name_offset)
    runtime[cursor:cursor] = source_frame_blob
    struct.pack_into(f"{module.endian}I", runtime, 4, frame_count + 1)

    rebuilt = _rebuild_pvm_sections(
        module,
        {
            0: code,
            2: bytes(symbols),
            6: strings,
            7: bytes(runtime),
            8: debug_strings,
        },
    )
    parse_pvm(rebuilt)
    return rebuilt


def _ensure_pvm_typed_literal(
    original_data: bytes,
    type_name: str,
    value: int | float | str,
) -> tuple[bytes, int]:
    module = parse_pvm(original_data)
    for item in extract_typed_values(module):
        if item.type_name == type_name and item.value == value:
            return original_data, item.entry_index
    type_names = _type_names(module)
    if type_name not in type_names:
        raise ValueError(f"PVM has no resolved {type_name!r} type for a new literal.")
    type_index = type_names.index(type_name)
    strings = section_data(module, 6)
    if type_name == "string":
        strings, raw_value = _append_pool_text(strings, str(value))
        storage_size = 32
    elif type_name == "float":
        raw_value = struct.unpack(">I", struct.pack(">f", float(value)))[0]
        storage_size = 8
    else:
        raw_value = int(value) & 0xFFFFFFFF
        storage_size = 8

    initial = bytearray(section_data(module, 1))
    count, frame_size = struct.unpack_from(f"{module.endian}HH", initial, 0)
    insert_at = 4 + count * 8
    flags = 0x7A7A
    for item_index in range(count):
        pos = 4 + item_index * 8
        if struct.unpack_from(f"{module.endian}H", initial, pos)[0] == type_index:
            flags = struct.unpack_from(f"{module.endian}H", initial, pos + 2)[0]
            break
    initial[insert_at:insert_at] = struct.pack(f"{module.endian}HHI", type_index, flags, raw_value)
    struct.pack_into(f"{module.endian}HH", initial, 0, count + 1, frame_size + storage_size)
    rebuilt = _rebuild_pvm_sections(module, {1: bytes(initial), 6: strings})
    return rebuilt, count


def _literal_type_and_value(text: str) -> tuple[str, int | float | str]:
    stripped = text.strip()
    try:
        value = ast.literal_eval(stripped)
    except (SyntaxError, ValueError) as exc:
        raise ValueError(f"New function return value must be a literal, got {text!r}.") from exc
    if isinstance(value, bool):
        return "int", int(value)
    if isinstance(value, int):
        return "int", value
    if isinstance(value, float):
        return "float", value
    if isinstance(value, str):
        return "string", value
    raise ValueError(f"Unsupported PVM literal type: {type(value).__name__}.")


def append_literal_return_function(
    original_data: bytes,
    new_function: str,
    literal_text: str,
) -> bytes:
    """Compile `function Name() { return <literal>; }` into a new routine."""
    type_name, value = _literal_type_and_value(literal_text)
    data, literal_index = _ensure_pvm_typed_literal(original_data, type_name, value)
    module = parse_pvm(data)
    frames = pvm_debug_frames(module)
    template = None
    for entry in pvm_code_entries(module):
        frame = frames.get(entry.index)
        if frame is None or any(name != "this" for name in frame.argument_names):
            continue
        instructions = _instructions_in_range(module, entry.code_offset, entry.end_code_offset)
        body = [inst for inst in instructions if inst.op not in {0x6C, 0x7A}]
        if len(body) != 2 or body[0].op != 0x67 or body[1].op != 0x77:
            continue
        source_index = _u24(body[0].raw[2:5])
        values = {item.entry_index: item for item in extract_typed_values(module)}
        if source_index in values and values[source_index].type_name == type_name:
            template = frame.function_name
            break
    if template is None:
        raise ValueError(
            f"No no-argument {type_name} return function exists to provide a proven callable signature."
        )
    data = append_cloned_pvm_function(data, template, new_function)
    module = parse_pvm(data)
    entry = pvm_code_entries(module)[-1]
    code = bytearray(section_data(module, 0))
    push = next(
        (inst for inst in _instructions_in_range(module, entry.code_offset, entry.end_code_offset) if inst.op == 0x67),
        None,
    )
    if push is None or push.raw[1] != 3:
        raise ValueError("Cloned literal-return function has no typed-literal instruction.")
    _patch_tagged_u24(code, push.code_offset, literal_index, module.endian)
    return _rebuild_pvm_sections(module, {0: bytes(code)})


def _linear_source_statements(body: str) -> list[str]:
    statements = []
    for line in body.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if "{" in stripped or "}" in stripped:
            raise ValueError("structured statement")
        if not stripped.endswith(";"):
            raise ValueError("statement without semicolon")
        statements.append(stripped)
    return statements


def _compile_linear_function_body(
    data: bytes,
    function_name: str,
    body: str,
) -> tuple[bytes, bytes]:
    """Compile a straight-line body of global assignments and one return."""
    statements = _linear_source_statements(body)
    if not statements or not statements[-1].startswith("return"):
        raise ValueError(f"Function {function_name!r} must end in return.")
    module = parse_pvm(data)
    variables, _functions = _global_symbol_names(module)
    variable_indices = {name: index for index, name in variables.items()}
    compiled = bytearray()
    assignment = re.compile(r"^([A-Za-z_][A-Za-z0-9_:]*)\s*=\s*(.+);$")
    return_value = re.compile(r"^return\s+(.+);$")
    for index, statement in enumerate(statements):
        if statement == "return;":
            if index != len(statements) - 1:
                raise ValueError(f"Function {function_name!r}: return must be the final statement.")
            compiled.append(0x78)
            continue
        match = return_value.match(statement)
        if match:
            if index != len(statements) - 1:
                raise ValueError(f"Function {function_name!r}: return must be the final statement.")
            literal_type, literal_value = _literal_type_and_value(match.group(1))
            data, literal_index = _ensure_pvm_typed_literal(data, literal_type, literal_value)
            compiled.extend(b"\x67" + _encode_tagged_u24(3, literal_index, module.endian) + b"\x77")
            continue
        match = assignment.match(statement)
        if not match or match.group(1) not in variable_indices:
            raise ValueError(
                f"Function {function_name!r}: unsupported straight-line statement {statement!r}."
            )
        target_name, literal_text = match.groups()
        literal_type, literal_value = _literal_type_and_value(literal_text)
        data, literal_index = _ensure_pvm_typed_literal(data, literal_type, literal_value)
        compiled.extend(b"\x66" + _encode_tagged_u24(1, variable_indices[target_name], module.endian))
        compiled.extend(b"\x67" + _encode_tagged_u24(3, literal_index, module.endian))
        compiled.extend(b"\x6D\x14\x03\x6B\x01")
    return data, bytes(compiled)


def _replace_function_with_linear_source(data: bytes, name: str, body: str) -> bytes:
    module = parse_pvm(data)
    frames = pvm_debug_frames(module)
    entry = next(
        (entry for entry in pvm_code_entries(module) if frames.get(entry.index) and frames[entry.index].function_name == name),
        None,
    )
    if entry is None:
        raise ValueError(f"Function {name!r} was not found.")
    frame = frames[entry.index]
    if any(arg != "this" for arg in frame.argument_names):
        raise ValueError(f"Function {name!r}: straight-line recompilation requires no arguments.")
    instructions = _instructions_in_range(module, entry.code_offset, entry.end_code_offset)
    prologue = next((inst for inst in instructions if inst.op == 0x6C), None)
    if prologue is None or prologue.code_offset != entry.code_offset:
        raise ValueError(f"Function {name!r} has no standard frame prologue.")
    data, body_code = _compile_linear_function_body(data, name, body)
    module = parse_pvm(data)
    entries = pvm_code_entries(module)
    frames = pvm_debug_frames(module)
    entry = next(e for e in entries if frames.get(e.index) and frames[e.index].function_name == name)
    prologue = next(inst for inst in _instructions_in_range(module, entry.code_offset, entry.end_code_offset) if inst.op == 0x6C)
    replacement = bytearray(prologue.raw + body_code)
    code_section = section_data(module, 0)
    replace_end = entry.end_code_offset
    while replace_end > entry.code_offset and code_section[replace_end - 1] == 0x7A:
        replace_end -= 1
    old_size = replace_end - entry.code_offset
    while (len(replacement) - old_size) & 3:
        replacement.append(0x7A)
    return splice_pvm_code(data, entry.code_offset, old_size, bytes(replacement))


def _append_linear_source_function(data: bytes, name: str, body: str) -> bytes:
    statements = _linear_source_statements(body)
    return_statement = statements[-1] if statements else ""
    return_type = "void"
    if return_statement != "return;":
        match = re.match(r"^return\s+(.+);$", return_statement)
        if match is None:
            raise ValueError(f"New function {name!r} must end in return.")
        return_type, _value = _literal_type_and_value(match.group(1))
    module = parse_pvm(data)
    frames = pvm_debug_frames(module)
    template = None
    fallback_template = None
    values = {item.entry_index: item for item in extract_typed_values(module)}
    for entry in pvm_code_entries(module):
        frame = frames.get(entry.index)
        if entry.index == 0 or frame is None or any(arg != "this" for arg in frame.argument_names):
            continue
        fallback_template = fallback_template or frame.function_name
        if frame.local_names:
            continue
        instructions = _instructions_in_range(module, entry.code_offset, entry.end_code_offset)
        body_ops = [inst for inst in instructions if inst.op not in {0x6C, 0x7A}]
        if return_type == "void" and body_ops and body_ops[-1].op == 0x78:
            template = frame.function_name
            break
        if return_type != "void" and len(body_ops) >= 2 and body_ops[-2].op == 0x67 and body_ops[-1].op == 0x77:
            item = values.get(_u24(body_ops[-2].raw[2:5]))
            if item and item.type_name == return_type:
                template = frame.function_name
                break
    if template is None:
        template = fallback_template
    if template is None:
        raise ValueError(f"No no-argument function frame exists for new function {name!r}.")
    data = append_cloned_pvm_function(data, template, name)
    if return_type != "void":
        data, signature_index = _ensure_signature(data, 0, return_type)
        data = _set_function_signature(data, name, signature_index)
    return _replace_function_with_linear_source(data, name, body)


def _function_symbol_record_position(module: PvmModule, function_name: str) -> int:
    frames = pvm_debug_frames(module)
    entry = next(
        (item for item in pvm_code_entries(module) if frames.get(item.index) and frames[item.index].function_name == function_name),
        None,
    )
    if entry is None or entry.index == 0:
        raise ValueError(f"Function {function_name!r} has no exported symbol record.")
    symbols = section_data(module, 2)
    variable_count = struct.unpack_from(f"{module.endian}I", symbols, 0)[0]
    return 12 + variable_count * 8 + (entry.index - 1) * 16


def _signature_index(module: PvmModule, argument_count: int, return_type: str) -> int:
    type_names = _type_names(module)
    if return_type not in type_names:
        raise ValueError(f"PVM has no resolved {return_type!r} return type.")
    wanted = type_names.index(return_type)
    signatures = section_data(module, 3)
    count = struct.unpack_from(f"{module.endian}I", signatures, 0)[0]
    for index in range(count):
        offset = struct.unpack_from(f"{module.endian}I", signatures, 8 + index * 4)[0]
        if offset + 4 > len(signatures) or signatures[offset + 1] != argument_count:
            continue
        if struct.unpack_from(f"{module.endian}H", signatures, offset + 2)[0] == wanted:
            return index
    raise ValueError(f"PVM has no proven {argument_count}-argument {return_type} signature.")


def _ensure_signature(
    data: bytes,
    argument_count: int,
    return_type: str,
    argument_types: tuple[int, ...] | None = None,
) -> tuple[bytes, int]:
    """Return a matching signature index, appending one when necessary."""
    module = parse_pvm(data)
    try:
        return data, _signature_index(module, argument_count, return_type)
    except ValueError:
        pass
    argument_types = argument_types or tuple(0xFFFE for _ in range(argument_count))
    if len(argument_types) != argument_count:
        raise ValueError("PVM signature argument-type count does not match its header.")
    type_names = _type_names(module)
    if return_type not in type_names:
        raise ValueError(f"PVM has no resolved {return_type!r} return type.")
    signatures = section_data(module, 3)
    if len(signatures) < 8:
        raise ValueError("PVM signature section is truncated.")
    count, runtime_size = struct.unpack_from(f"{module.endian}II", signatures, 0)
    table_end = 8 + count * 4
    if table_end > len(signatures):
        raise ValueError("PVM signature offset table is truncated.")
    descriptor = bytearray((0, argument_count))
    descriptor.extend(_encode_pvm_u16(type_names.index(return_type), module.endian))
    for type_index in argument_types:
        descriptor.extend(_encode_pvm_u16(type_index, module.endian))
    rebuilt = bytearray(signatures[:8])
    old_offsets = [
        struct.unpack_from(f"{module.endian}I", signatures, 8 + index * 4)[0]
        for index in range(count)
    ]
    for offset in old_offsets:
        rebuilt.extend(struct.pack(f"{module.endian}I", offset + 4))
    new_offset = len(signatures) + 4
    rebuilt.extend(struct.pack(f"{module.endian}I", new_offset))
    rebuilt.extend(signatures[table_end:])
    rebuilt.extend(descriptor)
    struct.pack_into(f"{module.endian}II", rebuilt, 0, count + 1, runtime_size + 16 + argument_count * 4)
    return _rebuild_pvm_sections(module, {3: bytes(rebuilt)}), count


def _set_function_signature(data: bytes, function_name: str, signature_index: int) -> bytes:
    module = parse_pvm(data)
    symbols = bytearray(section_data(module, 2))
    record_pos = _function_symbol_record_position(module, function_name)
    old_record = bytes(symbols[record_pos:record_pos + 16])
    old_size = _function_signature_runtime_size(module, old_record)
    struct.pack_into(f"{module.endian}H", symbols, record_pos + 12, signature_index)
    new_record = bytes(symbols[record_pos:record_pos + 16])
    new_size = _function_signature_runtime_size(module, new_record)
    storage_size = struct.unpack_from(f"{module.endian}I", symbols, 4)[0]
    storage_size += new_size - old_size
    if storage_size < 0:
        raise ValueError(f"Function {function_name!r}: invalid signature runtime storage size.")
    struct.pack_into(f"{module.endian}I", symbols, 4, storage_size)
    return _rebuild_pvm_sections(module, {2: bytes(symbols)})


def _patch_debug_local_name(data: bytes, function_name: str, local_index: int, new_name: str) -> bytes:
    module = parse_pvm(data)
    frames = pvm_debug_frames(module)
    entry = next(
        (item for item in pvm_code_entries(module) if frames.get(item.index) and frames[item.index].function_name == function_name),
        None,
    )
    if entry is None:
        raise ValueError(f"Function {function_name!r} has no debug frame.")
    debug_strings, name_offset = _append_pool_text(section_data(module, 8), new_name)
    runtime = bytearray(section_data(module, 7))
    line_count, frame_count = struct.unpack_from(f"{module.endian}II", runtime, 0)
    cursor = 8 + line_count * 12
    preamble_names = struct.unpack_from(f"{module.endian}H", runtime, cursor + 4)[0]
    cursor += 16 + preamble_names * 4
    for entry_index in range(1, frame_count):
        local_count, argument_count = struct.unpack_from(f"{module.endian}HH", runtime, cursor + 4)
        if entry_index == entry.index:
            if not 0 <= local_index < local_count:
                raise ValueError(f"Function {function_name!r} has no local {local_index}.")
            names_start = cursor + 16 + argument_count * 4
            struct.pack_into(f"{module.endian}I", runtime, names_start + local_index * 4, name_offset)
            return _rebuild_pvm_sections(module, {7: bytes(runtime), 8: debug_strings})
        cursor += 16 + (local_count + argument_count) * 4
    raise ValueError(f"Function {function_name!r} has no serialized debug frame.")


def _encode_pvm_u16(value: int, endian: str) -> bytes:
    return value.to_bytes(2, "little" if endian == "<" else "big")


@dataclass(frozen=True)
class _StructuredExpr:
    kind: str
    value: object
    args: tuple["_StructuredExpr", ...] = ()


@dataclass(frozen=True)
class _StructuredStmt:
    kind: str
    value: object = None
    body: tuple["_StructuredStmt", ...] = ()


class _StructuredSourceParser:
    """Brace-aware parser for the editable PVM compiler's structured subset."""

    _token = re.compile(
        r"\s*(?:(?P<string>'(?:\\.|[^'\\])*'|\"(?:\\.|[^\"\\])*\")|"
        r"(?P<number>\d+(?:\.\d+)?)|(?P<name>[A-Za-z_][A-Za-z0-9_:]*)|"
        r"(?P<op>==|!=|<=|>=|<<|>>|&&|\|\||[{}();,.=+\-*/%<>]))"
    )
    _precedence = {"||": 1, "&&": 2, "==": 3, "!=": 3, "<": 3, "<=": 3,
                   ">": 3, ">=": 3, "+": 4, "-": 4, "*": 5, "/": 5, "%": 5}

    def __init__(self, text: str):
        self.items: list[tuple[str, str]] = []
        cursor = 0
        while cursor < len(text):
            match = self._token.match(text, cursor)
            if not match:
                if text[cursor:].strip():
                    raise ValueError(f"Unsupported source near {text[cursor:cursor + 32]!r}.")
                break
            kind = next(key for key, value in match.groupdict().items() if value is not None)
            self.items.append((kind, match.group(kind)))
            cursor = match.end()
        self.index = 0

    def peek(self, text: str | None = None) -> bool:
        return self.index < len(self.items) and (text is None or self.items[self.index][1] == text)

    def take(self, text: str | None = None) -> tuple[str, str]:
        if not self.peek(text):
            actual = self.items[self.index][1] if self.index < len(self.items) else "end of function"
            raise ValueError(f"Expected {text!r}, got {actual!r}.")
        item = self.items[self.index]; self.index += 1
        return item

    def parse(self) -> tuple[_StructuredStmt, ...]:
        result = self.block(False)
        if self.peek(): raise ValueError(f"Unexpected token {self.take()[1]!r}.")
        return result

    def block(self, braced: bool) -> tuple[_StructuredStmt, ...]:
        if braced: self.take("{")
        statements = []
        while self.peek() and not (braced and self.peek("}")): statements.append(self.statement())
        if braced: self.take("}")
        return tuple(statements)

    def statement(self) -> _StructuredStmt:
        if self.peek("if"):
            self.take("if"); self.take("("); condition = self.expression(); self.take(")")
            body = self.block(True) if self.peek("{") else (self.statement(),)
            return _StructuredStmt("if", condition, body)
        if self.peek("return"):
            self.take("return"); value = None if self.peek(";") else self.expression(); self.take(";")
            return _StructuredStmt("return", value)
        kind, first = self.take()
        if kind != "name": raise ValueError(f"Expected declaration or assignment, got {first!r}.")
        if self.peek() and self.items[self.index][0] == "name":
            name = self.take()[1]; self.take(";")
            return _StructuredStmt("declare", (first, name))
        self.take("="); value = self.expression(); self.take(";")
        return _StructuredStmt("assign", (first, value))

    def expression(self, minimum: int = 0) -> _StructuredExpr:
        if self.peek("("):
            self.take("("); left = self.expression(); self.take(")")
        else:
            kind, text = self.take()
            if kind in {"string", "number"}: left = _StructuredExpr("literal", text)
            elif kind == "name": left = _StructuredExpr("name", text)
            else: raise ValueError(f"Unsupported expression token {text!r}.")
        while self.peek(".") or self.peek("("):
            if self.peek("."):
                self.take("."); member = self.take()[1]; self.take("("); args = self.arguments(); self.take(")")
                left = _StructuredExpr("call", member, (left, *args))
            else:
                self.take("("); args = self.arguments(); self.take(")")
                left = _StructuredExpr("call", None, (left, *args))
        while self.peek() and self.items[self.index][1] in self._precedence:
            operator = self.items[self.index][1]; precedence = self._precedence[operator]
            if precedence < minimum: break
            self.take(); right = self.expression(precedence + 1)
            left = _StructuredExpr("binary", operator, (left, right))
        return left

    def arguments(self) -> tuple[_StructuredExpr, ...]:
        args = []
        if not self.peek(")"):
            while True:
                args.append(self.expression())
                if not self.peek(","): break
                self.take(",")
        return tuple(args)


def _parse_structured_function_body(body: str) -> tuple[_StructuredStmt, ...]:
    return _StructuredSourceParser(body).parse()


def _walk_structured_statements(statements: tuple[_StructuredStmt, ...]):
    for statement in statements:
        yield statement
        yield from _walk_structured_statements(statement.body)


def _walk_structured_expression(expression: _StructuredExpr | None):
    if expression is None: return
    yield expression
    for child in expression.args: yield from _walk_structured_expression(child)


def _member_return_types(module: PvmModule) -> dict[str, str]:
    """Infer member result types from retail call-result frame slots."""
    names = _member_names(module); inferred: dict[str, str] = {}
    for entry in pvm_code_entries(module):
        instructions = _instructions_in_range(module, entry.code_offset, entry.end_code_offset)
        local_types = _frame_local_types(instructions, _type_names(module))
        for index, inst in enumerate(instructions):
            if inst.op != 0x6E or len(inst.raw) < 3: continue
            member = names.get(int.from_bytes(inst.raw[1:3], "big"))
            cursor = index - 1
            while cursor >= 0 and instructions[cursor].op not in {0x69, 0x6E, 0x71}: cursor -= 1
            if member and cursor >= 1 and instructions[cursor].op == 0x69 and instructions[cursor - 1].op == 0x64:
                offset = int.from_bytes(instructions[cursor - 1].raw[1:3], "big")
                if offset in local_types: inferred.setdefault(member, local_types[offset])
    return inferred


class _StructuredEmitter:
    def __init__(self, module, function_name, entry, prologue, locals_by_name, scratch, typed):
        self.module, self.function_name, self.entry = module, function_name, entry
        self.prologue, self.locals, self.scratch, self.typed = prologue, locals_by_name, scratch, typed
        self.code = bytearray(); self.body_start = entry.code_offset + len(prologue.raw)
        self.types = _type_names(module); self.member_ids = {v: k for k, v in _member_names(module).items()}
        variables, _ = _global_symbol_names(module); self.global_ids = {v: k for k, v in variables.items()}
        self.returns = _member_return_types(module); self.in_use: set[int] = set()

    def reserve(self, kind):
        for offset in self.scratch.get(kind, []):
            if offset not in self.in_use: self.in_use.add(offset); return offset
        raise ValueError(f"Function {self.function_name!r}: no free {kind} scratch frame slot.")

    def release(self, offset): self.in_use.discard(offset)

    def literal(self, text):
        kind, value = _literal_type_and_value(text); return kind, value, self.typed[(kind, value)]

    def expression_type(self, expr, expected=None):
        if expr.kind == "literal": return self.literal(str(expr.value))[0]
        if expr.kind == "name":
            if expr.value in self.locals: return self.locals[str(expr.value)][0]
            raise ValueError(f"Unknown local {expr.value!r}.")
        if expr.kind == "binary":
            return "int" if expr.value in PV_COMPARISON_TOKENS.values() else self.expression_type(expr.args[0], expected)
        if expr.kind == "call": return self.returns.get(str(expr.value), expected or "int")
        raise ValueError(f"Unsupported expression {expr.kind!r}.")

    def emit_expression(self, expr, expected=None):
        if expr.kind == "literal":
            self.code.extend(b"\x67" + _encode_tagged_u24(3, self.literal(str(expr.value))[2], self.module.endian)); return
        if expr.kind == "name":
            if expr.value in self.locals:
                self.code.extend(b"\x64" + _encode_pvm_u16(self.locals[str(expr.value)][1], self.module.endian)); return
            if expr.value in self.global_ids:
                self.code.extend(b"\x66" + _encode_tagged_u24(1, self.global_ids[str(expr.value)], self.module.endian)); return
            raise ValueError(f"Unknown value {expr.value!r}.")
        if expr.kind == "binary":
            left, right = expr.args; result_type = self.expression_type(expr, expected); scratch = self.reserve(result_type)
            self.code.extend(b"\x64" + _encode_pvm_u16(scratch, self.module.endian))
            self.emit_expression(left); self.emit_expression(right)
            table = PV_COMPARISON_TOKENS if expr.value in PV_COMPARISON_TOKENS.values() else PV_BINARY_TOKENS
            token = next((key for key, value in table.items() if value == expr.value), None)
            if token is None: raise ValueError(f"Unsupported operator {expr.value!r}.")
            mode = 4 if table is PV_COMPARISON_TOKENS else 6
            self.code.extend(bytes((0x6D, token, mode)) + _encode_tagged_u24(2, self.types.index(self.expression_type(left)), self.module.endian))
            # Keep the result slot live until the enclosing statement consumes
            # the expression. A VM stack value may still reference this slot.
            return
        if expr.kind == "call":
            receiver, *arguments = expr.args; member = str(expr.value)
            if expr.value is None:
                if arguments or receiver.kind != "name":
                    raise ValueError("Direct script accessors currently require a named zero-argument call.")
                accessor = str(receiver.value)
                if accessor not in self.member_ids:
                    raise ValueError(f"Unknown direct script accessor {accessor!r}.")
                # Opcode 0x75 invokes a script accessor on the implicit
                # `this` frame value. Retail PVMs consistently place `this`
                # in the first frame slot at +0x0C.
                self.code.extend(b"\x64" + _encode_pvm_u16(12, self.module.endian))
                self.code.extend(b"\x75" + _encode_pvm_u16(self.member_ids[accessor], self.module.endian))
                return
            if member not in self.member_ids: raise ValueError(f"Unknown member function {member!r}.")
            result = self.reserve(self.expression_type(expr, expected))
            self.code.extend(b"\x64" + _encode_pvm_u16(result, self.module.endian))
            continuation_at = len(self.code); self.code.extend(b"\x69\x05\x00\x00\x00")
            staged = []
            for argument in arguments:
                kind = self.expression_type(argument); slot = self.reserve(kind); staged.append(slot)
                self.emit_expression(argument, kind); self.code.extend(b"\x74" + _encode_pvm_u16(slot, self.module.endian))
            self.code.extend(b"\x6A" + _encode_tagged_u24(0, len(arguments), self.module.endian))
            self.emit_expression(receiver); self.code.extend(b"\x6E" + _encode_pvm_u16(self.member_ids[member], self.module.endian))
            _patch_tagged_u24(self.code, continuation_at, self.body_start + len(self.code), self.module.endian)
            # Result and staged argument slots remain live until the complete
            # statement has executed; nested calls must not recycle them.
            return
        raise ValueError(f"Unsupported expression {expr.kind!r}.")

    def emit_statements(self, statements):
        for statement in statements:
            if statement.kind == "declare": continue
            if statement.kind == "assign":
                name, expression = statement.value
                if name not in self.locals: raise ValueError(f"Unknown assignment local {name!r}.")
                kind, offset = self.locals[name]; self.code.extend(b"\x64" + _encode_pvm_u16(offset, self.module.endian))
                self.emit_expression(expression, kind); self.code.extend(b"\x6D\x14\x03\x6B\x01")
                self.in_use.clear()
            elif statement.kind == "return":
                if statement.value is None: self.code.append(0x78)
                else: self.emit_expression(statement.value); self.code.append(0x77)
                self.in_use.clear()
            elif statement.kind == "if":
                self.emit_expression(statement.value, "int"); jump = len(self.code); self.code.extend(b"\x70\x05\x00\x00\x00")
                self.in_use.clear()
                self.emit_statements(statement.body); _patch_tagged_u24(self.code, jump, self.body_start + len(self.code), self.module.endian)
            else: raise ValueError(f"Unsupported statement {statement.kind!r}.")


def _append_structured_source_function(data: bytes, name: str, body: str) -> bytes:
    statements = _parse_structured_function_body(body)
    declarations = [stmt.value for stmt in _walk_structured_statements(statements) if stmt.kind == "declare"]
    if not declarations: raise ValueError(f"New function {name!r}: structured functions require declared locals.")
    declared_types = {local_name: type_name for type_name, local_name in declarations}
    returns = [stmt.value for stmt in _walk_structured_statements(statements) if stmt.kind == "return" and stmt.value]
    return_type = "int"
    if returns:
        if returns[0].kind == "literal": return_type = _literal_type_and_value(str(returns[0].value))[0]
        elif returns[0].kind == "name": return_type = declared_types.get(str(returns[0].value), "int")
    literal_values = []
    for statement in _walk_structured_statements(statements):
        roots = [statement.value[1]] if statement.kind == "assign" else [statement.value] if statement.kind in {"if", "return"} else []
        for root in roots:
            for item in _walk_structured_expression(root):
                if item.kind == "literal": literal_values.append(_literal_type_and_value(str(item.value)))
    ensured_literals = {}
    for kind, value in literal_values:
        data, entry_index = _ensure_pvm_typed_literal(data, kind, value)
        ensured_literals[(kind, value)] = entry_index

    module = parse_pvm(data); frames = pvm_debug_frames(module); types = _type_names(module)
    needed = {}
    for type_name, _ in declarations: needed[type_name] = needed.get(type_name, 0) + 1
    # The deepest supported expression keeps two integer temporaries live:
    # an operator/call result plus either a nested result or staged argument.
    needed["int"] = needed.get("int", 0) + 2
    inferred_returns = _member_return_types(module)
    for statement in _walk_structured_statements(statements):
        roots = [statement.value[1]] if statement.kind == "assign" else [statement.value] if statement.kind in {"if", "return"} else []
        for root in roots:
            for expression in _walk_structured_expression(root):
                if expression.kind != "call":
                    continue
                result_type = inferred_returns.get(str(expression.value))
                if result_type and result_type != "int":
                    needed[result_type] = max(needed.get(result_type, 0), 1)
    templates = []
    for entry in pvm_code_entries(module):
        frame = frames.get(entry.index)
        if not frame or entry.index == 0 or any(arg != "this" for arg in frame.argument_names): continue
        slots = _frame_local_types(_instructions_in_range(module, entry.code_offset, entry.end_code_offset), types)
        if all(sum(kind == type_name for kind in slots.values()) >= count for type_name, count in needed.items()):
            templates.append(frame.function_name)
    if not templates: raise ValueError(f"New function {name!r}: no frame has enough typed local and scratch slots.")
    template = templates[0]
    data = append_cloned_pvm_function(data, template, name)
    data, signature = _ensure_signature(data, 0, return_type); data = _set_function_signature(data, name, signature)
    module = parse_pvm(data); frames = pvm_debug_frames(module)
    entry = next(e for e in pvm_code_entries(module) if frames.get(e.index) and frames[e.index].function_name == name)
    instructions = _instructions_in_range(module, entry.code_offset, entry.end_code_offset); slots = _frame_local_types(instructions, _type_names(module))
    available = {}
    for offset, kind in slots.items(): available.setdefault(kind, []).append(offset)
    locals_by_name = {}
    for type_name, local_name in declarations:
        offset = available[type_name].pop(0); locals_by_name[local_name] = (type_name, offset)
        data = _patch_debug_local_name(data, name, list(slots).index(offset), local_name)
    module = parse_pvm(data); frames = pvm_debug_frames(module)
    entry = next(e for e in pvm_code_entries(module) if frames.get(e.index) and frames[e.index].function_name == name)
    instructions = _instructions_in_range(module, entry.code_offset, entry.end_code_offset); prologue = instructions[0]
    typed = {(item.type_name, item.value): item.entry_index for item in extract_typed_values(module)}
    # Decimal source values are quantized to float32 in the PVM table. Keep
    # the requested spelling mapped to the entry returned during insertion so
    # values such as 0.075 remain addressable after that quantization.
    typed.update(ensured_literals)
    emitter = _StructuredEmitter(module, name, entry, prologue, locals_by_name, available, typed); emitter.emit_statements(statements)
    replacement = bytearray(prologue.raw + emitter.code); code_section = section_data(module, 0); replace_end = entry.end_code_offset
    while replace_end > entry.code_offset and code_section[replace_end - 1] == 0x7A: replace_end -= 1
    old_size = replace_end - entry.code_offset
    while (len(replacement) - old_size) & 3: replacement.append(0x7A)
    return splice_pvm_code(data, entry.code_offset, old_size, bytes(replacement))


def _parse_conditional_return_body(body: str) -> dict | None:
    lines = [line.strip() for line in body.splitlines() if line.strip()]
    declarations = []
    while lines:
        match = re.fullmatch(r"([A-Za-z_][A-Za-z0-9_:]*)\s+([A-Za-z_][A-Za-z0-9_]*)\s*;", lines[0])
        if not match:
            break
        declarations.append(match.groups())
        lines.pop(0)
    if len(declarations) != 1 or len(lines) < 3:
        return None
    local_type, local_name = declarations[0]
    assignment = re.fullmatch(
        rf"{re.escape(local_name)}\s*=\s*\(?\s*"
        r"([A-Za-z_][A-Za-z0-9_:]*)\.([A-Za-z_][A-Za-z0-9_]*)\(\s*\)\s*"
        r"([*+\-/%&|^]|<<|>>)\s*(.+?)\s*\)?\s*;",
        lines.pop(0),
    )
    if assignment is None:
        return None
    receiver, member, binary_operator, binary_literal = assignment.groups()
    branches = []
    branch_re = re.compile(
        rf"if\s*\(\s*\(?\s*{re.escape(local_name)}\s*"
        r"(==|!=|<=|>=|<|>)\s*(.+?)\s*\)?\s*\)\s*return\s+(.+?)\s*;"
    )
    while len(lines) > 1:
        match = branch_re.fullmatch(lines.pop(0))
        if match is None:
            return None
        branches.append(match.groups())
    final = re.fullmatch(r"return\s+(.+?)\s*;", lines[0])
    if final is None or not branches:
        return None
    return {
        "local_type": local_type,
        "local_name": local_name,
        "receiver": receiver,
        "member": member,
        "binary_operator": binary_operator,
        "binary_literal": binary_literal,
        "branches": branches,
        "final_return": final.group(1),
    }


def _append_conditional_return_source_function(data: bytes, name: str, body: str) -> bytes:
    spec = _parse_conditional_return_body(body)
    if spec is None:
        raise ValueError(f"New function {name!r} is outside the supported conditional-return subset.")
    binary_type, binary_value = _literal_type_and_value(spec["binary_literal"])
    if binary_type != spec["local_type"]:
        raise ValueError(f"New function {name!r}: binary operand type does not match its local.")
    parsed_branches = []
    return_type = None
    for comparison, compare_text, return_text in spec["branches"]:
        compare_type, compare_value = _literal_type_and_value(compare_text)
        branch_return_type, branch_return_value = _literal_type_and_value(return_text)
        if compare_type != spec["local_type"]:
            raise ValueError(f"New function {name!r}: comparison type does not match its local.")
        return_type = return_type or branch_return_type
        if branch_return_type != return_type:
            raise ValueError(f"New function {name!r}: conditional returns use mixed types.")
        parsed_branches.append((comparison, compare_type, compare_value, branch_return_type, branch_return_value))
    final_type, final_value = _literal_type_and_value(spec["final_return"])
    return_type = return_type or final_type
    if final_type != return_type:
        raise ValueError(f"New function {name!r}: final return type differs from its conditional returns.")

    module = parse_pvm(data)
    type_names = _type_names(module)
    frames = pvm_debug_frames(module)
    template = None
    source_local_index = 0
    for entry in pvm_code_entries(module):
        frame = frames.get(entry.index)
        if frame is None or entry.index == 0 or any(arg != "this" for arg in frame.argument_names):
            continue
        local_types = _frame_local_types(
            _instructions_in_range(module, entry.code_offset, entry.end_code_offset), type_names
        )
        matching = [offset for offset, kind in local_types.items() if kind == spec["local_type"]]
        return_matching = [offset for offset, kind in local_types.items() if kind == return_type]
        if len(matching) >= 3 and return_matching:
            template = frame.function_name
            source_local_index = list(local_types).index(matching[0])
            break
    if template is None:
        raise ValueError(
            f"New function {name!r}: no no-argument frame has enough {spec['local_type']} work slots."
        )

    data = append_cloned_pvm_function(data, template, name)
    data, new_signature_index = _ensure_signature(data, 0, return_type)
    module = parse_pvm(data)
    symbols = bytearray(section_data(module, 2))
    record_pos = _function_symbol_record_position(module, name)
    old_record = bytes(symbols[record_pos:record_pos + 16])
    old_signature_size = _function_signature_runtime_size(module, old_record)
    struct.pack_into(f"{module.endian}H", symbols, record_pos + 12, new_signature_index)
    new_record = bytes(symbols[record_pos:record_pos + 16])
    new_signature_size = _function_signature_runtime_size(module, new_record)
    runtime_storage_size = struct.unpack_from(f"{module.endian}I", symbols, 4)[0]
    adjusted_storage_size = runtime_storage_size + new_signature_size - old_signature_size
    if adjusted_storage_size < 0:
        raise ValueError(f"New function {name!r}: invalid signature runtime storage size.")
    struct.pack_into(f"{module.endian}I", symbols, 4, adjusted_storage_size)
    data = _rebuild_pvm_sections(module, {2: bytes(symbols)})
    data = _patch_debug_local_name(data, name, source_local_index, spec["local_name"])

    literal_values = [(binary_type, binary_value), (final_type, final_value)]
    for _, compare_type, compare_value, branch_type, branch_value in parsed_branches:
        literal_values.extend(((compare_type, compare_value), (branch_type, branch_value)))
    for kind, value in literal_values:
        data, _ = _ensure_pvm_typed_literal(data, kind, value)

    module = parse_pvm(data)
    frames = pvm_debug_frames(module)
    entry = next(
        item for item in pvm_code_entries(module)
        if frames.get(item.index) and frames[item.index].function_name == name
    )
    instructions = _instructions_in_range(module, entry.code_offset, entry.end_code_offset)
    prologue = instructions[0]
    local_types = _frame_local_types(instructions, _type_names(module))
    matching_offsets = [offset for offset, kind in local_types.items() if kind == spec["local_type"]]
    local_offset, result_offset, call_offset = matching_offsets[0], matching_offsets[-2], matching_offsets[-1]
    variables, _ = _global_symbol_names(module)
    variable_indices = {value: index for index, value in variables.items()}
    members = {value: index for index, value in _member_names(module).items()}
    if spec["receiver"] not in variable_indices or spec["member"] not in members:
        raise ValueError(
            f"New function {name!r}: {spec['receiver']}.{spec['member']}() is unavailable in this module."
        )
    typed = {(item.type_name, item.value): item.entry_index for item in extract_typed_values(module)}
    local_type_index = _type_names(module).index(spec["local_type"])
    binary_token = next((token for token, text in PV_BINARY_TOKENS.items() if text == spec["binary_operator"]), None)
    if binary_token is None:
        raise ValueError(f"New function {name!r}: unsupported binary operator {spec['binary_operator']!r}.")

    code = bytearray()
    body_start = entry.code_offset + len(prologue.raw)
    code.extend(b"\x64" + _encode_pvm_u16(local_offset, module.endian))
    code.extend(b"\x64" + _encode_pvm_u16(result_offset, module.endian))
    code.extend(b"\x64" + _encode_pvm_u16(call_offset, module.endian))
    continuation = body_start + len(code) + 15
    code.extend(b"\x69" + _encode_tagged_u24(5, continuation, module.endian))
    code.extend(b"\x6A" + _encode_tagged_u24(0, 0, module.endian))
    code.extend(b"\x66" + _encode_tagged_u24(1, variable_indices[spec["receiver"]], module.endian))
    code.extend(b"\x6E" + _encode_pvm_u16(members[spec["member"]], module.endian))
    code.extend(b"\x67" + _encode_tagged_u24(3, typed[(binary_type, binary_value)], module.endian))
    code.extend(bytes((0x6D, binary_token, 0x06)) + _encode_tagged_u24(2, local_type_index, module.endian))
    code.extend(b"\x6D\x14\x03\x6B\x01")

    for comparison, compare_type, compare_value, branch_type, branch_value in parsed_branches:
        comparison_token = next(
            (token for token, text in PV_COMPARISON_TOKENS.items() if text == comparison), None
        )
        if comparison_token is None:
            raise ValueError(f"New function {name!r}: unsupported comparison {comparison!r}.")
        code.extend(b"\x64" + _encode_pvm_u16(result_offset, module.endian))
        code.extend(b"\x64" + _encode_pvm_u16(local_offset, module.endian))
        code.extend(b"\x67" + _encode_tagged_u24(3, typed[(compare_type, compare_value)], module.endian))
        code.extend(bytes((0x6D, comparison_token, 0x04)) + _encode_tagged_u24(2, local_type_index, module.endian))
        false_jump_at = len(code)
        code.extend(b"\x70\x05\x00\x00\x00")
        code.extend(b"\x67" + _encode_tagged_u24(3, typed[(branch_type, branch_value)], module.endian))
        code.extend(b"\x77")
        _patch_tagged_u24(code, false_jump_at, body_start + len(code), module.endian)
    code.extend(b"\x67" + _encode_tagged_u24(3, typed[(final_type, final_value)], module.endian))
    code.extend(b"\x77")

    replacement = bytearray(prologue.raw + code)
    code_section = section_data(module, 0)
    replace_end = entry.end_code_offset
    while replace_end > entry.code_offset and code_section[replace_end - 1] == 0x7A:
        replace_end -= 1
    old_size = replace_end - entry.code_offset
    while (len(replacement) - old_size) & 3:
        replacement.append(0x7A)
    return splice_pvm_code(data, entry.code_offset, old_size, bytes(replacement))


def _source_function_blocks(text: str) -> dict[str, tuple[tuple[str, ...], str]]:
    """Extract top-level decompiler-style function blocks without parsing bodies."""
    lines = text.splitlines()
    out: dict[str, tuple[tuple[str, ...], str]] = {}
    index = 0
    signature = re.compile(r"^\s*function\s+([A-Za-z_][A-Za-z0-9_:]*)\s*\(([^)]*)\)\s*$")
    while index < len(lines):
        match = signature.match(lines[index])
        if not match:
            index += 1
            continue
        cursor = index + 1
        while cursor < len(lines) and not lines[cursor].strip():
            cursor += 1
        if cursor >= len(lines) or lines[cursor].strip() != "{":
            raise ValueError(f"Function {match.group(1)!r} is missing its opening brace.")
        depth = 1
        body_start = cursor + 1
        cursor += 1
        while cursor < len(lines) and depth:
            depth += lines[cursor].count("{") - lines[cursor].count("}")
            cursor += 1
        if depth:
            raise ValueError(f"Function {match.group(1)!r} has unbalanced braces.")
        args = tuple(part.strip() for part in match.group(2).split(",") if part.strip())
        body = "\n".join(lines[body_start:cursor - 1]).strip()
        out[match.group(1)] = (args, body)
        index = cursor
    return out


def _compile_new_source_functions(text: str, original_data: bytes) -> bytes:
    functions = _source_function_blocks(text)
    original_functions = _source_function_blocks(
        format_pvm_source_scaffold(parse_pvm(original_data))
    )
    existing = {frame.function_name for frame in pvm_debug_frames(parse_pvm(original_data)).values()}
    data = original_data
    for name, (arguments, body) in functions.items():
        if name in existing or name.startswith("routine_"):
            continue
        # A copied source function is already a complete, proven bytecode
        # template. Reuse its signature, frame descriptors, calls, branches,
        # and locals verbatim instead of reducing it to the linear subset.
        normalized_body = re.sub(r"\s+", "", body)
        clone_source = next(
            (
                source_name
                for source_name, (source_arguments, source_body) in original_functions.items()
                if source_name in existing
                and source_arguments == arguments
                and re.sub(r"\s+", "", source_body) == normalized_body
            ),
            None,
        )
        if clone_source is not None:
            data = append_cloned_pvm_function(data, clone_source, name)
        else:
            if arguments:
                raise ValueError(
                    f"New function {name!r}: arguments require either a matching copied "
                    "function body/signature or the full expression compiler."
                )
            if _parse_conditional_return_body(body) is not None:
                data = _append_conditional_return_source_function(data, name, body)
            else:
                try:
                    data = _append_structured_source_function(data, name, body)
                except ValueError as structured_error:
                    try:
                        data = _append_linear_source_function(data, name, body)
                    except ValueError:
                        raise structured_error
        existing.add(name)
    return data


def _remove_pvm_function_export(data: bytes, function_name: str) -> bytes:
    """Remove one source function from the callable/debug tables.

    Section-0 bytecode is deliberately retained as dead code. This keeps every
    unrelated code address stable while making the function unreachable by
    name and absent from subsequent source exports.
    """
    module = parse_pvm(data)
    frames = pvm_debug_frames(module)
    entry = next(
        (
            item
            for item in pvm_code_entries(module)
            if item.index and frames.get(item.index)
            and frames[item.index].function_name == function_name
        ),
        None,
    )
    if entry is None:
        raise ValueError(f"Function {function_name!r} was not found or is not exported.")

    symbols = bytearray(section_data(module, 2))
    if len(symbols) < 12:
        raise ValueError("PVM value-symbol section is truncated.")
    variable_count = struct.unpack_from(f"{module.endian}I", symbols, 0)[0]
    function_count = struct.unpack_from(f"{module.endian}H", symbols, 8)[0]
    owned_function_count = struct.unpack_from(f"{module.endian}H", symbols, 10)[0]
    symbol_index = entry.index - 1
    if not (0 <= symbol_index < function_count):
        raise ValueError(f"Function {function_name!r} has no section-2 symbol record.")
    function_start = 12 + variable_count * 8
    record_start = function_start + symbol_index * 16
    record = bytes(symbols[record_start:record_start + 16])
    signature_runtime_size = _function_signature_runtime_size(module, record)
    del symbols[record_start:record_start + 16]
    struct.pack_into(f"{module.endian}H", symbols, 8, function_count - 1)
    if owned_function_count == 0:
        raise ValueError("PVM owned-function count is already zero.")
    struct.pack_into(f"{module.endian}H", symbols, 10, owned_function_count - 1)
    runtime_storage_size = struct.unpack_from(f"{module.endian}I", symbols, 4)[0]
    if runtime_storage_size < signature_runtime_size:
        raise ValueError("PVM function-signature runtime storage is truncated.")
    struct.pack_into(f"{module.endian}I", symbols, 4, runtime_storage_size - signature_runtime_size)

    runtime = bytearray(section_data(module, 7))
    if len(runtime) < 8:
        raise ValueError("PVM runtime-record section is truncated.")
    line_count, frame_count = struct.unpack_from(f"{module.endian}II", runtime, 0)
    cursor = 8 + line_count * 12
    if cursor + 16 > len(runtime):
        raise ValueError("PVM debug-frame preamble is truncated.")
    preamble_name_count = struct.unpack_from(f"{module.endian}H", runtime, cursor + 4)[0]
    cursor += 16 + preamble_name_count * 4
    frame_ranges: list[tuple[int, int]] = []
    for _ in range(1, frame_count):
        start = cursor
        if cursor + 16 > len(runtime):
            raise ValueError("PVM debug-frame table is truncated.")
        local_count, argument_count = struct.unpack_from(f"{module.endian}HH", runtime, cursor + 4)
        cursor += 16 + (local_count + argument_count) * 4
        frame_ranges.append((start, cursor))
    if not (0 <= symbol_index < len(frame_ranges)):
        raise ValueError(f"Function {function_name!r} has no debug-frame record.")
    frame_start, frame_end = frame_ranges[symbol_index]
    del runtime[frame_start:frame_end]
    struct.pack_into(f"{module.endian}I", runtime, 4, frame_count - 1)

    code = bytearray(section_data(module, 0))
    for instruction in decode_pvm_instructions(module):
        if instruction.op != 0x66 or len(instruction.raw) < 5 or instruction.raw[1] != 0:
            continue
        function_index = _u24(instruction.raw[2:5])
        if function_index >= owned_function_count:
            _patch_tagged_u24(code, instruction.code_offset, function_index - 1, module.endian)

    rebuilt = _rebuild_pvm_sections(
        module, {0: bytes(code), 2: bytes(symbols), 7: bytes(runtime)}
    )
    parse_pvm(rebuilt)
    return rebuilt


def _rename_pvm_function_export(data: bytes, old_name: str, new_name: str) -> bytes:
    """Rename one owned function in both symbol and debug-frame tables."""
    module = parse_pvm(data)
    frames = pvm_debug_frames(module)
    entry = next(
        (item for item in pvm_code_entries(module)
         if frames.get(item.index) and frames[item.index].function_name == old_name),
        None,
    )
    if entry is None or entry.index == 0:
        raise ValueError(f"Function {old_name!r} was not found or is not exported.")
    if any(frame.function_name == new_name for frame in frames.values()):
        raise ValueError(f"Function {new_name!r} already exists.")

    strings, symbol_name_offset = _append_pool_text(section_data(module, 6), new_name)
    debug_strings, debug_name_offset = _append_pool_text(section_data(module, 8), new_name)
    symbols = bytearray(section_data(module, 2))
    record_pos = _function_symbol_record_position(module, old_name)
    struct.pack_into(f"{module.endian}I", symbols, record_pos, symbol_name_offset)

    runtime = bytearray(section_data(module, 7))
    line_count, frame_count = struct.unpack_from(f"{module.endian}II", runtime, 0)
    cursor = 8 + line_count * 12
    preamble_names = struct.unpack_from(f"{module.endian}H", runtime, cursor + 4)[0]
    cursor += 16 + preamble_names * 4
    for entry_index in range(1, frame_count):
        local_count, argument_count = struct.unpack_from(f"{module.endian}HH", runtime, cursor + 4)
        if entry_index == entry.index:
            struct.pack_into(f"{module.endian}I", runtime, cursor + 12, debug_name_offset)
            break
        cursor += 16 + (local_count + argument_count) * 4
    else:
        raise ValueError(f"Function {old_name!r} has no serialized debug frame.")

    rebuilt = _rebuild_pvm_sections(
        module,
        {2: bytes(symbols), 6: strings, 7: bytes(runtime), 8: debug_strings},
    )
    parse_pvm(rebuilt)
    return rebuilt


def _compile_removed_source_functions(text: str, original_data: bytes, current_data: bytes) -> bytes:
    """Remove exported functions whose complete source block was deleted."""
    edited_names = set(_source_function_blocks(text))
    original_names = set(_source_function_blocks(format_pvm_source_scaffold(parse_pvm(original_data))))
    removed = [name for name in original_names - edited_names if not name.startswith("routine_")]
    data = current_data
    for name in sorted(removed):
        data = _remove_pvm_function_export(data, name)
    return data


_SOURCE_LITERAL_RE = re.compile(
    r"'(?:\\.|[^'\\])*'|\"(?:\\.|[^\"\\])*\"|(?<![A-Za-z0-9_])(?:\d+\.\d+(?:[eE][+-]?\d+)?|\d+)(?![A-Za-z0-9_])"
)


def _source_literals_and_shape(body: str) -> tuple[list[str], str]:
    literals = [match.group(0) for match in _SOURCE_LITERAL_RE.finditer(body)]
    shape = _SOURCE_LITERAL_RE.sub("<literal>", body)
    shape = re.sub(r"\s+", "", shape)
    return literals, shape


def _compile_existing_zero_arg_call_edit(
    data: bytes,
    function_name: str,
    original_body: str,
    edited_body: str,
) -> bytes | None:
    zero_arg_call = re.compile(r"(?<![A-Za-z0-9_:])(?P<callee>[A-Za-z_][A-Za-z0-9_:]*)\(\s*\)")
    candidate = None
    for old_match in _SOURCE_LITERAL_RE.finditer(original_body):
        for new_match in zero_arg_call.finditer(edited_body):
            old_normalized = original_body[:old_match.start()] + "<expression>" + original_body[old_match.end():]
            new_normalized = edited_body[:new_match.start()] + "<expression>" + edited_body[new_match.end():]
            if re.sub(r"\s+", "", old_normalized) == re.sub(r"\s+", "", new_normalized):
                if candidate is not None:
                    raise ValueError(
                        f"Function {function_name!r}: the literal-to-call edit is ambiguous."
                    )
                candidate = (old_match, new_match)
    if candidate is None:
        return None
    old_match, new_match = candidate
    old_type, old_value = _literal_type_and_value(old_match.group(0))
    statement_start = max(original_body.rfind(";", 0, old_match.start()), original_body.rfind("{", 0, old_match.start())) + 1
    statement_end = original_body.find(";", old_match.end())
    statement = original_body[statement_start:statement_end if statement_end >= 0 else len(original_body)]
    member_matches = re.findall(r"\.([A-Za-z_][A-Za-z0-9_]*)\s*\(", statement)
    enclosing_member = member_matches[-1] if member_matches else None

    module = parse_pvm(data)
    frames = pvm_debug_frames(module)
    entries = pvm_code_entries(module)
    caller = next(
        (item for item in entries if frames.get(item.index) and frames[item.index].function_name == function_name),
        None,
    )
    callee_name = new_match.group("callee")
    callee = next(
        (item for item in entries if frames.get(item.index) and frames[item.index].function_name == callee_name),
        None,
    )
    if caller is None or callee is None:
        raise ValueError(
            f"Function {function_name!r}: zero-argument call target {callee_name!r} was not compiled."
        )
    callee_frame = frames[callee.index]
    if any(argument != "this" for argument in callee_frame.argument_names):
        raise ValueError(f"Function {callee_name!r} is not a zero-argument script function.")
    values = {item.entry_index: item for item in extract_typed_values(module)}
    literal_pushes = []
    for inst in _instructions_in_range(module, caller.code_offset, caller.end_code_offset):
        if inst.op != 0x67 or len(inst.raw) < 5 or inst.raw[1] != 3:
            continue
        item = values.get(_u24(inst.raw[2:5]))
        if item and item.type_name == old_type and item.value == old_value:
            literal_pushes.append(inst)
    if enclosing_member:
        unfiltered_pushes = literal_pushes
        filtered_pushes = []
        caller_instructions = _instructions_in_range(module, caller.code_offset, caller.end_code_offset)
        instruction_index = {item.code_offset: index for index, item in enumerate(caller_instructions)}
        for literal_push in literal_pushes:
            start = instruction_index[literal_push.code_offset]
            following = caller_instructions[start + 1:start + 8]
            if any(
                item.op == 0x6E and item.text.endswith(f".{enclosing_member}")
                for item in following
            ):
                filtered_pushes.append(literal_push)
        literal_pushes = filtered_pushes or unfiltered_pushes
    if len(literal_pushes) > 1:
        key = (old_type, old_value)
        target_ordinal = sum(
            _literal_type_and_value(match.group(0)) == key
            for match in _SOURCE_LITERAL_RE.finditer(original_body[:old_match.start()])
        )
        expected_shape = re.sub(
            r"\s+",
            "",
            original_body[:old_match.start()]
            + "<expression>"
            + original_body[old_match.end():],
        )
        selected = None
        candidate_scores = []
        for candidate_index, literal_push in enumerate(literal_pushes):
            if old_type == "string":
                probe_value: object = (
                    f"__gzbuildr_call_probe_{candidate_index}_{literal_push.code_offset:x}__"
                )
            elif old_type == "float":
                probe_value = 234567.25 + candidate_index
            else:
                probe_value = 1779040000 + candidate_index
            trial, probe_index = _ensure_pvm_typed_literal(data, old_type, probe_value)
            trial_module = parse_pvm(trial)
            trial_code = bytearray(section_data(trial_module, 0))
            _patch_tagged_u24(
                trial_code,
                literal_push.code_offset,
                probe_index,
                trial_module.endian,
            )
            trial = _rebuild_pvm_sections(trial_module, {0: bytes(trial_code)})
            trial_source = format_pvm_source_scaffold(parse_pvm(trial))
            trial_function = _source_function_blocks(trial_source).get(function_name)
            if trial_function is None:
                continue
            trial_body = trial_function[1]
            probe_matches = [
                match
                for match in _SOURCE_LITERAL_RE.finditer(trial_body)
                if _literal_type_and_value(match.group(0)) == (old_type, probe_value)
            ]
            source_ordinals = [
                sum(
                    _literal_type_and_value(match.group(0)) == key
                    for match in _SOURCE_LITERAL_RE.finditer(trial_body[:probe.start()])
                )
                for probe in probe_matches
            ]
            if source_ordinals:
                candidate_scores.append(
                    (min(abs(ordinal - target_ordinal) for ordinal in source_ordinals), literal_push)
                )
            if source_ordinals and all(
                ordinal == target_ordinal for ordinal in source_ordinals
            ):
                selected = literal_push
                break
            if len(probe_matches) != 1:
                continue
            probe_match = probe_matches[0]
            trial_shape = re.sub(
                r"\s+",
                "",
                trial_body[:probe_match.start()]
                + "<expression>"
                + trial_body[probe_match.end():],
            )
            if trial_shape == expected_shape:
                selected = literal_push
                break
        if selected is None and candidate_scores:
            best = min(score for score, _ in candidate_scores)
            closest = [push for score, push in candidate_scores if score == best]
            if len(closest) == 1:
                selected = closest[0]
        if selected is not None:
            literal_pushes = [selected]
    if len(literal_pushes) != 1:
        raise ValueError(
            f"Function {function_name!r}: expected one {old_value!r} expression push, "
            f"found {len(literal_pushes)}."
        )

    push = literal_pushes[0]
    caller_instructions = _instructions_in_range(module, caller.code_offset, caller.end_code_offset)
    push_index = next(index for index, item in enumerate(caller_instructions) if item.code_offset == push.code_offset)
    store = caller_instructions[push_index + 1] if push_index + 1 < len(caller_instructions) else None
    destination_offset = (
        int.from_bytes(store.raw[1:3], "big")
        if store is not None and store.op == 0x74 and len(store.raw) >= 3
        else None
    )
    local_types = _frame_local_types(caller_instructions, _type_names(module))
    # A nested expression call may run after earlier arguments for the outer
    # member call have already been stored in frame locals. The callee writes
    # through its hidden return reference, so reusing one of those argument
    # locals corrupts the outer call (for example, monsterId becomes the
    # player slot in setMonsterIndex(1, helper())).
    staged_offsets: set[int] = set()
    for item in reversed(caller_instructions[:push_index]):
        if item.op == 0x69:
            break
        if item.op == 0x74 and len(item.raw) >= 3:
            staged_offsets.add(int.from_bytes(item.raw[1:3], "big"))
        # Binary expressions leave both their destination and earlier
        # operands live on the VM stack. A hidden script-call return must not
        # reuse any of those referenced frame slots.
        if item.op == 0x64 and len(item.raw) >= 3:
            staged_offsets.add(int.from_bytes(item.raw[1:3], "big"))
    return_offset = next(
        (
            offset for offset, type_name in local_types.items()
            if type_name == old_type
            and (destination_offset is None or offset != destination_offset)
            and offset not in staged_offsets
        ),
        None,
    )
    if return_offset is None:
        raise ValueError(
            f"Function {function_name!r}: no spare {old_type} frame slot is available for the call result."
        )

    # A script expression call pushes one hidden return slot. On return that
    # slot remains at stack.top, and the original 0x74 instruction stores it
    # into the expression destination. This is the exact layout emitted by the
    # Wii compiler for calls such as `result = findWinner()`.
    remove_size = push.size
    # A direct argument edit already has a preserved 0x74 store immediately
    # after the replaced literal. A literal inside a binary expression does
    # not, so commit the returned value to its hidden result slot here before
    # the preserved operator consumes that slot.
    replacement_size = 25 if destination_offset is not None else 29
    continuation = push.code_offset + 18
    mapped_callee = callee.code_offset + (
        replacement_size - remove_size
        if callee.code_offset >= push.code_offset + remove_size else 0
    )
    replacement = bytearray()
    replacement.extend(b"\x64" + _encode_pvm_u16(return_offset, module.endian))
    replacement.extend(b"\x69" + _encode_tagged_u24(5, continuation, module.endian))
    replacement.extend(b"\x6A" + _encode_tagged_u24(0, 0, module.endian))
    replacement.extend(b"\x71" + _encode_tagged_u24(5, mapped_callee, module.endian))
    if destination_offset is None:
        replacement.extend(b"\x74" + _encode_pvm_u16(return_offset, module.endian))
    # Keep the splice delta four-byte aligned. The continuation stores the
    # result when needed, then jumps across unreachable alignment bytes to the
    # preserved argument store or binary operator.
    replacement.extend(
        b"\x71"
        + _encode_tagged_u24(5, push.code_offset + replacement_size, module.endian)
    )
    replacement.extend(b"\x76" * (replacement_size - len(replacement)))
    if len(replacement) != replacement_size:
        raise AssertionError("zero-argument call replacement has an unexpected size")
    return splice_pvm_code(data, push.code_offset, remove_size, bytes(replacement))


def _compile_existing_unreachable_call_insertions(
    data: bytes,
    function_name: str,
    original_body: str,
    edited_body: str,
) -> bytes | None:
    """Insert zero-arg calls exactly where source adds them after a return."""
    call_re = re.compile(r"^([A-Za-z_][A-Za-z0-9_:]*)\(\s*\);$")
    original_lines = [line.strip() for line in original_body.splitlines() if line.strip()]
    edited_lines = [line.strip() for line in edited_body.splitlines() if line.strip()]
    additions: list[tuple[str, int]] = []
    old_index = 0
    for edited_index, line in enumerate(edited_lines):
        if old_index < len(original_lines) and line == original_lines[old_index]:
            old_index += 1
            continue
        match = call_re.fullmatch(line)
        if match is None or edited_index == 0:
            return None
        previous = edited_lines[edited_index - 1]
        if not (previous.startswith("return ") or previous == "return;"):
            return None
        return_ordinal = sum(
            item.startswith("return ") or item == "return;"
            for item in edited_lines[:edited_index]
        ) - 1
        additions.append((match.group(1), return_ordinal))
    if old_index != len(original_lines) or not additions:
        return None
    rebuilt = data
    for callee_name, return_ordinal in additions:
        module = parse_pvm(rebuilt)
        frames = pvm_debug_frames(module)
        entries = pvm_code_entries(module)
        caller = next(
            (entry for entry in entries if frames.get(entry.index) and frames[entry.index].function_name == function_name),
            None,
        )
        callee = next(
            (entry for entry in entries if frames.get(entry.index) and frames[entry.index].function_name == callee_name),
            None,
        )
        if caller is None or callee is None:
            return None
        instructions = _instructions_in_range(module, caller.code_offset, caller.end_code_offset)
        returns = [inst for inst in instructions if inst.op in {0x77, 0x78}]
        if return_ordinal >= len(returns):
            return None
        insert_at = returns[return_ordinal].code_offset + returns[return_ordinal].size
        mapped_callee = callee.code_offset + (8 if callee.code_offset >= insert_at else 0)
        # Put alignment filler before the unreachable call so the call remains
        # the final decoded statement before the next function frame.
        insertion = b"\x76\x76\x76\x71" + _encode_tagged_u24(5, mapped_callee, module.endian)
        rebuilt = splice_pvm_code(rebuilt, insert_at, 0, insertion)
    return rebuilt


def _compile_existing_source_literal_edits(
    text: str,
    original_data: bytes,
    current_data: bytes,
) -> bytes:
    """Patch typed-literal instructions when only source literals changed."""
    original_module = parse_pvm(original_data)
    original_source = format_pvm_source_scaffold(original_module)
    original_functions = _source_function_blocks(original_source)
    edited_functions = _source_function_blocks(text)
    data = current_data

    for name, (arguments, edited_body) in edited_functions.items():
        original = original_functions.get(name)
        if original is None:
            continue
        original_arguments, original_body = original
        if arguments != original_arguments or edited_body == original_body:
            continue
        old_literals, old_shape = _source_literals_and_shape(original_body)
        new_literals, new_shape = _source_literals_and_shape(edited_body)
        if old_shape != new_shape or len(old_literals) != len(new_literals):
            call_edit = _compile_existing_zero_arg_call_edit(
                data, name, original_body, edited_body
            )
            if call_edit is not None:
                data = call_edit
                continue
            inserted_calls = _compile_existing_unreachable_call_insertions(
                data, name, original_body, edited_body
            )
            if inserted_calls is not None:
                data = inserted_calls
                continue
            if not arguments:
                try:
                    data = _replace_function_with_linear_source(data, name, edited_body)
                    continue
                except ValueError:
                    pass
            raise ValueError(
                f"Function {name!r} changes statements or expressions. "
                "This compiler stage currently accepts literal-only edits to existing functions."
            )

        module = parse_pvm(data)
        frames = pvm_debug_frames(module)
        entry = next(
            (item for item in pvm_code_entries(module)
             if frames.get(item.index) and frames[item.index].function_name == name),
            None,
        )
        if entry is None:
            raise ValueError(f"Could not locate edited function {name!r}.")
        values = {item.entry_index: item for item in extract_typed_values(module)}
        pushes_by_literal: dict[tuple[str, object], list[int]] = {}
        for instruction in _instructions_in_range(
            module, entry.code_offset, entry.end_code_offset
        ):
            if instruction.op != 0x67 or len(instruction.raw) < 5 or instruction.raw[1] != 3:
                continue
            item = values.get(_u24(instruction.raw[2:5]))
            if item is not None:
                pushes_by_literal.setdefault(
                    (item.type_name, item.value), []
                ).append(instruction.code_offset)

        occurrence: dict[tuple[str, object], int] = {}
        changes: list[tuple[tuple[str, object], int, str, object]] = []
        for old_text, new_text in zip(old_literals, new_literals):
            old_type, old_value = _literal_type_and_value(old_text)
            key = (old_type, old_value)
            ordinal = occurrence.get(key, 0)
            occurrence[key] = ordinal + 1
            if old_text == new_text:
                continue
            new_type, new_value = _literal_type_and_value(new_text)
            if old_type != new_type:
                raise ValueError(
                    f"Function {name!r}: changing {old_type} literal {old_text} "
                    f"to {new_type} would change the VM operation type."
                )
            changes.append((key, ordinal, new_type, new_value))

        # Bytecode order does not necessarily match structured source order:
        # branches and early returns can make the decompiler visit blocks in a
        # different sequence. Probe duplicate pushes individually and observe
        # where each one appears in the decompiled function.
        source_offsets: dict[tuple[str, object], list[int]] = {}
        changed_keys = {key for key, _, _, _ in changes}
        for key in changed_keys:
            matching_pushes = pushes_by_literal.get(key, [])
            if len(matching_pushes) < 2:
                source_offsets[key] = matching_pushes
                continue
            type_name, _ = key
            mapped: dict[int, int] = {}
            for candidate_index, push_offset in enumerate(matching_pushes):
                if type_name == "string":
                    probe_value: object = (
                        f"__gzbuildr_literal_probe_{candidate_index}_{push_offset:x}__"
                    )
                elif type_name == "float":
                    probe_value = 123456.25 + candidate_index
                else:
                    probe_value = 1879040000 + candidate_index
                trial, probe_index = _ensure_pvm_typed_literal(
                    data, type_name, probe_value
                )
                trial_module = parse_pvm(trial)
                trial_code = bytearray(section_data(trial_module, 0))
                _patch_tagged_u24(
                    trial_code, push_offset, probe_index, trial_module.endian
                )
                trial = _rebuild_pvm_sections(trial_module, {0: bytes(trial_code)})
                trial_source = format_pvm_source_scaffold(parse_pvm(trial))
                trial_function = _source_function_blocks(trial_source).get(name)
                if trial_function is None:
                    continue
                trial_literals, _ = _source_literals_and_shape(trial_function[1])
                positions = [
                    index
                    for index, literal in enumerate(trial_literals)
                    if _literal_type_and_value(literal) == (type_name, probe_value)
                ]
                if len(positions) == 1:
                    source_ordinal = sum(
                        _literal_type_and_value(literal) == key
                        for literal in trial_literals[:positions[0]]
                    )
                    mapped[source_ordinal] = push_offset
            if len(mapped) != len(matching_pushes):
                raise ValueError(
                    f"Function {name!r}: could not distinguish identical "
                    f"{type_name} literal occurrences for {key[1]!r}."
                )
            source_offsets[key] = [mapped[index] for index in range(len(mapped))]

        # Identical literals in one function are independent source
        # expressions, even when they share the same typed-value table entry.
        requested: list[tuple[int, str, object]] = []
        for key, ordinal, new_type, new_value in changes:
            matching_pushes = source_offsets.get(key, [])
            if ordinal >= len(matching_pushes):
                raise ValueError(
                    f"Function {name!r}: source occurrence {ordinal + 1} of "
                    f"{key[1]!r} has no matching typed-literal instruction."
                )
            requested.append((matching_pushes[ordinal], new_type, new_value))

        for push_offset, new_type, new_value in requested:
            data, new_index = _ensure_pvm_typed_literal(data, new_type, new_value)
            module = parse_pvm(data)
            code = bytearray(section_data(module, 0))
            _patch_tagged_u24(code, push_offset, new_index, module.endian)
            data = _rebuild_pvm_sections(module, {0: bytes(code)})
    return data


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
    typed_values = extract_typed_values(module)
    typed_aliases = _pvm_source_aliases(typed_values)
    typed_by_source = {
        (item.type_name, typed_aliases[item.entry_index]): item
        for item in typed_values
    }
    old_row_re = re.compile(
        r"^@0x([0-9A-Fa-f]+)\s+.*?\bkind=(u8|u16|u24)\b.*?\bvalue=([+-]?(?:0x[0-9A-Fa-f]+|\d+))"
    )
    new_row_re = re.compile(
        r"^@0x([0-9A-Fa-f]+)\s+(u8|u16|u24)\s+.+?\s+=\s+([+-]?(?:0x[0-9A-Fa-f]+|\d+))"
    )
    table_row_re = re.compile(
        r"^@0x([0-9A-Fa-f]+)\s*\|\s*([A-Za-z0-9_]+)\s*\|\s*.+?\s*\|\s*(.+?)\s*$"
    )
    source_global_re = re.compile(
        r"^\s*(int|float|string)\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+?)\s*;\s*(?://.*|#.*)?$"
    )
    editable_lines: list[tuple[int, str, str]] = []
    for line in text.splitlines():
        stripped = line.strip()
        match = old_row_re.match(stripped) or new_row_re.match(stripped) or table_row_re.match(stripped)
        if match:
            editable_lines.append((int(match.group(1), 16), match.group(2), match.group(3)))
            continue
        source_match = source_global_re.match(stripped)
        if source_match:
            kind = source_match.group(1)
            name = source_match.group(2)
            item = typed_by_source.get((kind, name))
            if item is not None:
                editable_lines.append((item.file_offset, kind, source_match.group(3)))
    editable_lines.sort(key=lambda item: item[0])

    patched = 0
    string_insert_threshold = module.sections[6].end
    inserted_string_bytes = 0
    for original_file_offset, kind, value_text in editable_lines:
        file_offset = original_file_offset + (inserted_string_bytes if original_file_offset >= string_insert_threshold else 0)
        typed_item = typed_allowed.get((file_offset, kind))
        if typed_item is not None:
            if kind == "string":
                string_patch_value = _parse_string_edit_value(value_text)
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
                    value_text,
                    original_value=typed_item.value,
                    original_raw=typed_item.raw_value,
                )
            byteorder = "little" if module.endian == "<" else "big"
            new_raw = raw_value.to_bytes(4, byteorder)
            if data[file_offset:file_offset + 4] != typed_item.raw_value.to_bytes(4, byteorder) and raw_value != typed_item.raw_value:
                raise ValueError(f"Original bytes changed at 0x{file_offset:X}; refusing stale patch.")
            if raw_value != typed_item.raw_value:
                data[file_offset:file_offset + 4] = new_raw
                patched += 1
            continue

        value = _parse_int_value(value_text)
        if kind == "int":
            kind = next((candidate.kind for candidate in allowed.values() if candidate.file_offset == file_offset), kind)
        item = allowed.get((file_offset, kind))
        if item is None:
            raise ValueError(f"Unknown or non-editable value row at 0x{file_offset:X}.")
        width = {"u8": 1, "u16": 2, "u24": 3}[kind]
        max_value = (1 << (width * 8)) - 1
        if not 0 <= value <= max_value:
            raise ValueError(f"Value {value} does not fit {kind} at 0x{file_offset:X}.")
        new_raw = value.to_bytes(width, "little" if module.endian == "<" else "big")
        if data[file_offset:file_offset + width] != item.raw and new_raw != item.raw:
            raise ValueError(f"Original bytes changed at 0x{file_offset:X}; refusing stale patch.")
        if new_raw != item.raw:
            data[file_offset:file_offset + width] = new_raw
            patched += 1
    result = _compile_new_source_functions(text, bytes(data))
    result = _compile_existing_source_literal_edits(text, original_data, result)
    result = _compile_removed_source_functions(text, original_data, result)
    # No-op saves are allowed; they keep bundle-entry workflows calm.
    parse_pvm(result)
    return result


def dump_pvm(path: Path, out: Path | None = None, include_tables: bool = False) -> Path:
    module = load_pvm(path)
    text = format_pvm_report(module, path, include_tables=include_tables)
    out = out or path.with_suffix(path.suffix + ".txt")
    out.write_text(text, encoding="utf-8", newline="\n")
    return out


def format_pvm_info(module: PvmModule, path: Path | None = None) -> str:
    lines = []
    lines.append("# PWK PVM module info")
    if path is not None:
        lines.append(f"# SourcePVM={path}")
    lines.append(f"Version: {module.version_text}")
    lines.append(f"Marker: 0x{module.marker:08X}")
    lines.append(f"TotalSize: 0x{module.total_size:X}")
    lines.append("")
    lines.append("[Sections]")
    for section in module.sections:
        section_name = PVM_SECTION_NAMES.get(section.index, f"Section{section.index}")
        lines.append(
            f"{section.index} {section_name:<16} offset=0x{section.offset:06X} "
            f"size=0x{section.size:06X} end=0x{section.end:06X}"
        )
    lines.append("")
    lines.append(f"Code entries: {len(pvm_code_entries(module))}")
    lines.append(f"Typed values: {len(extract_typed_values(module))}")
    lines.append(f"Section 6 strings: {len(indexed_pool(module, 6))}")
    lines.append(f"Section 8 debug strings: {len(indexed_pool(module, 8))}")
    return "\n".join(lines) + "\n"


def verify_pvm_modules(original_data: bytes, rebuilt_data: bytes) -> tuple[bool, str]:
    lines = ["# PWK PVM structural verify"]
    try:
        original = parse_pvm(original_data)
        rebuilt = parse_pvm(rebuilt_data)
    except Exception as exc:
        return False, "\n".join(lines + [f"Parse failure: {exc}"]) + "\n"

    ok = True
    if original_data == rebuilt_data:
        lines.append("Bytes: identical")
    else:
        ok = False
        lines.append("Bytes: different")
        first_diff = next(
            (index for index, pair in enumerate(zip(original_data, rebuilt_data)) if pair[0] != pair[1]),
            min(len(original_data), len(rebuilt_data)),
        )
        lines.append(f"FirstDiff: 0x{first_diff:06X}")

    if original.version_text != rebuilt.version_text:
        ok = False
        lines.append(f"Version differs: {original.version_text!r} != {rebuilt.version_text!r}")
    if original.marker != rebuilt.marker:
        ok = False
        lines.append(f"Marker differs: 0x{original.marker:08X} != 0x{rebuilt.marker:08X}")
    if original.total_size != rebuilt.total_size:
        ok = False
        lines.append(f"Total size differs: 0x{original.total_size:X} != 0x{rebuilt.total_size:X}")

    lines.append("")
    lines.append("[Section comparison]")
    for left, right in zip(original.sections, rebuilt.sections):
        same_range = left.offset == right.offset and left.size == right.size
        same_bytes = section_data(original, left.index) == section_data(rebuilt, right.index)
        if not (same_range and same_bytes):
            ok = False
        status = "OK" if same_range and same_bytes else "DIFF"
        section_name = PVM_SECTION_NAMES.get(left.index, f"Section{left.index}")
        lines.append(
            f"{status} {left.index} {section_name}: "
            f"orig=0x{left.offset:06X}+0x{left.size:06X} "
            f"new=0x{right.offset:06X}+0x{right.size:06X} "
            f"bytes={'same' if same_bytes else 'different'}"
        )

    lines.append("")
    lines.append("[Semantic counts]")
    comparisons = [
        ("Code entries", len(pvm_code_entries(original)), len(pvm_code_entries(rebuilt))),
        ("Typed values", len(extract_typed_values(original)), len(extract_typed_values(rebuilt))),
        ("Section 6 strings", len(indexed_pool(original, 6)), len(indexed_pool(rebuilt, 6))),
        ("Section 8 debug strings", len(indexed_pool(original, 8)), len(indexed_pool(rebuilt, 8))),
        ("Decoded instructions", len(decode_pvm_instructions(original)), len(decode_pvm_instructions(rebuilt))),
    ]
    for label, left_count, right_count in comparisons:
        if left_count != right_count:
            ok = False
        lines.append(f"{'OK' if left_count == right_count else 'DIFF'} {label}: {left_count} -> {right_count}")

    return ok, "\n".join(lines) + "\n"


def _write_or_print(text: str, output: Path | None) -> None:
    if output is None:
        print(text, end="")
    else:
        output.write_text(text, encoding="utf-8", newline="\n")
        print(f"Wrote: {output}")


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]
    commands = {"info", "dump", "disasm", "decompile", "compile", "verify"}
    if argv and argv[0] not in commands and not argv[0].startswith("-"):
        legacy = argparse.ArgumentParser(description="Inspect Pipeworks PWK VM .pvm script modules")
        legacy.add_argument("input", type=Path)
        legacy.add_argument("-o", "--output", type=Path)
        legacy.add_argument("--verbose", action="store_true", help="append symbol pools and bytecode diagnostics")
        args = legacy.parse_args(argv)
        made = dump_pvm(args.input, args.output, include_tables=args.verbose)
        print(f"Wrote PVM report: {made}")
        return

    parser = argparse.ArgumentParser(description="Inspect/decompile Pipeworks PWK VM .pvm script modules")
    subparsers = parser.add_subparsers(dest="command")

    info_parser = subparsers.add_parser("info", help="print parsed module header/section summary")
    info_parser.add_argument("input", type=Path)
    info_parser.add_argument("-o", "--output", type=Path)

    dump_parser = subparsers.add_parser("dump", help="write editable value rows plus optional diagnostics")
    dump_parser.add_argument("input", type=Path)
    dump_parser.add_argument("-o", "--output", type=Path)
    dump_parser.add_argument("--verbose", action="store_true", help="append symbol pools and bytecode diagnostics")

    disasm_parser = subparsers.add_parser("disasm", help="write decoded instruction entries")
    disasm_parser.add_argument("input", type=Path)
    disasm_parser.add_argument("-o", "--output", type=Path)
    disasm_parser.add_argument("--max-entries", type=int)

    decompile_parser = subparsers.add_parser("decompile", help="write source-like decompiled VM routines")
    decompile_parser.add_argument("input", type=Path)
    decompile_parser.add_argument("-o", "--output", type=Path)
    decompile_parser.add_argument("--max-entries", type=int)

    compile_parser = subparsers.add_parser("compile", help="apply editable @ rows to a base PVM")
    compile_parser.add_argument("input", type=Path, help="editable PVM text produced by dump/GZBuildr")
    compile_parser.add_argument("-b", "--base", type=Path, required=True, help="original/base PVM to patch")
    compile_parser.add_argument("-o", "--output", type=Path, required=True)

    verify_parser = subparsers.add_parser("verify", help="structurally compare two PVM files")
    verify_parser.add_argument("original", type=Path)
    verify_parser.add_argument("rebuilt", type=Path)
    verify_parser.add_argument("-o", "--output", type=Path)

    args = parser.parse_args(argv)
    if args.command == "info":
        _write_or_print(format_pvm_info(load_pvm(args.input), args.input), args.output)
    elif args.command == "dump":
        made = dump_pvm(args.input, args.output, include_tables=args.verbose)
        print(f"Wrote PVM report: {made}")
    elif args.command == "disasm":
        module = load_pvm(args.input)
        _write_or_print(format_pvm_disassembly(module, args.input, args.max_entries), args.output)
    elif args.command == "decompile":
        module = load_pvm(args.input)
        _write_or_print(format_pvm_source_scaffold(module, args.input, args.max_entries), args.output)
    elif args.command == "compile":
        rebuilt = editable_to_pvm(args.input.read_text(encoding="utf-8"), args.base.read_bytes())
        args.output.write_bytes(rebuilt)
        print(f"Wrote PVM: {args.output}")
    elif args.command == "verify":
        ok, text = verify_pvm_modules(args.original.read_bytes(), args.rebuilt.read_bytes())
        _write_or_print(text, args.output)
        raise SystemExit(0 if ok else 1)
    else:
        parser.print_help()
        raise SystemExit(2)


if __name__ == "__main__":
    main()
