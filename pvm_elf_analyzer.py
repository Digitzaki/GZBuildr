#!/usr/bin/env python3
"""
Lightweight ELF/DOL analysis helpers for Pipeworks PWK VM research.

The Godzilla Wii/GC script modules are PWK "PVM" bytecode files. This helper
parses the supplied PowerPC ELF enough to extract symbols, locate VM routines,
and produce reusable notes for improving pvm_script_tool.py.
"""
from __future__ import annotations

import argparse
import re
import struct
from dataclasses import dataclass
from pathlib import Path


PVM_KEYWORDS = (
    "PVirtualMachine",
    "PVMachine",
    "PVModule",
    "PVLoadedModule",
    "PVModuleMgr",
    "PVModuleCache",
    "PVModuleBuilder",
    "PVDebugger",
    "PVAdapter",
    "PVFrame",
    "PVStack",
    "PVOp",
    "PScript",
    "PSymbol",
    "PFuncSymbol",
    "PVarSymbol",
    "PVariable",
    "ParserType",
    "PPToken",
)


@dataclass(frozen=True)
class ElfSection:
    index: int
    name: str
    type: int
    flags: int
    addr: int
    offset: int
    size: int
    link: int
    info: int
    addralign: int
    entsize: int


@dataclass(frozen=True)
class ElfSymbol:
    index: int
    name: str
    value: int
    size: int
    info: int
    shndx: int


def _cstr(data: bytes, offset: int) -> str:
    end = data.find(b"\0", offset)
    if end < 0:
        end = len(data)
    return data[offset:end].decode("utf-8", errors="replace")


class ElfImage:
    def __init__(self, path: Path):
        self.path = path
        self.data = path.read_bytes()
        if self.data[:4] != b"\x7fELF":
            raise ValueError("Not an ELF file.")
        if self.data[4] != 1 or self.data[5] != 2:
            raise ValueError("Expected 32-bit big-endian ELF.")
        self.endian = ">"
        self.sections = self._read_sections()
        self.symbols = self._read_symbols()

    def _read_sections(self):
        header = struct.unpack_from(self.endian + "HHIIIIIHHHHHH", self.data, 16)
        e_shoff = header[5]
        e_shentsize = header[10]
        e_shnum = header[11]
        e_shstrndx = header[12]
        raw = []
        for index in range(e_shnum):
            values = struct.unpack_from(self.endian + "IIIIIIIIII", self.data, e_shoff + index * e_shentsize)
            raw.append((index, values))
        shstr_values = raw[e_shstrndx][1]
        shstr = self.data[shstr_values[4]:shstr_values[4] + shstr_values[5]]
        sections = []
        for index, values in raw:
            name = _cstr(shstr, values[0])
            sections.append(ElfSection(index, name, *values[1:]))
        return sections

    def _read_symbols(self):
        symbols = []
        for section in self.sections:
            if section.type != 2 or section.entsize == 0:
                continue
            str_section = self.sections[section.link]
            strings = self.data[str_section.offset:str_section.offset + str_section.size]
            count = section.size // section.entsize
            for index in range(count):
                offset = section.offset + index * section.entsize
                st_name, value, size, info, _other, shndx = struct.unpack_from(
                    self.endian + "IIIBBH", self.data, offset
                )
                name = _cstr(strings, st_name) if st_name else ""
                if name:
                    symbols.append(ElfSymbol(index, name, value, size, info, shndx))
        return symbols

    def va_to_offset(self, addr: int) -> int | None:
        for section in self.sections:
            if section.type == 8:
                continue
            if section.addr <= addr < section.addr + section.size:
                return section.offset + (addr - section.addr)
        return None

    def bytes_at(self, addr: int, size: int) -> bytes:
        offset = self.va_to_offset(addr)
        if offset is None:
            raise ValueError(f"Address 0x{addr:X} is not file-backed.")
        return self.data[offset:offset + size]

    def find_symbols(self, pattern: str):
        regex = re.compile(pattern)
        return [symbol for symbol in self.symbols if regex.search(symbol.name)]


def ppc_branch_target(addr: int, word: int) -> int | None:
    opcode = word >> 26
    if opcode == 18:
        li = word & 0x03FFFFFC
        if li & 0x02000000:
            li -= 0x04000000
        aa = (word >> 1) & 1
        return li if aa else (addr + li)
    if opcode == 16:
        bd = word & 0xFFFC
        if bd & 0x8000:
            bd -= 0x10000
        aa = (word >> 1) & 1
        return bd if aa else (addr + bd)
    return None


def ppc_mnemonic(addr: int, word: int) -> str:
    opcode = word >> 26
    rt = (word >> 21) & 31
    ra = (word >> 16) & 31
    rb = (word >> 11) & 31
    imm = word & 0xFFFF
    simm = imm - 0x10000 if imm & 0x8000 else imm
    if word == 0x4E800020:
        return "blr"
    if word == 0x4E800421:
        return "bctrl"
    if word == 0x7C0802A6:
        return "mflr r0"
    if word == 0x7C0803A6:
        return "mtlr r0"
    if opcode == 14:
        return f"addi r{rt}, r{ra}, {simm}"
    if opcode == 15:
        return f"addis r{rt}, r{ra}, {simm}"
    if opcode == 32:
        return f"lwz r{rt}, {simm}(r{ra})"
    if opcode == 33:
        return f"lwzu r{rt}, {simm}(r{ra})"
    if opcode == 34:
        return f"lbz r{rt}, {simm}(r{ra})"
    if opcode == 36:
        return f"stw r{rt}, {simm}(r{ra})"
    if opcode == 37:
        return f"stwu r{rt}, {simm}(r{ra})"
    if opcode == 38:
        return f"stb r{rt}, {simm}(r{ra})"
    if opcode == 40:
        return f"lhz r{rt}, {simm}(r{ra})"
    if opcode == 44:
        return f"sth r{rt}, {simm}(r{ra})"
    if opcode == 10:
        return f"cmplwi cr{(word >> 23) & 7}, r{ra}, 0x{imm:X}"
    if opcode == 11:
        return f"cmpwi cr{(word >> 23) & 7}, r{ra}, {simm}"
    if opcode in (16, 18):
        target = ppc_branch_target(addr, word)
        lk = "l" if word & 1 else ""
        return f"b{lk} 0x{target:08X}" if target is not None else f"branch 0x{word:08X}"
    if opcode == 19:
        xo = (word >> 1) & 0x3FF
        if xo == 16:
            return "bclr"
        if xo == 528:
            return "bcctr"
    if opcode == 31:
        xo = (word >> 1) & 0x3FF
        if xo == 23:
            return f"lwzx r{rt}, r{ra}, r{rb}"
        if xo == 87:
            return f"lbzx r{rt}, r{ra}, r{rb}"
        if xo == 266:
            return f"add r{rt}, r{ra}, r{rb}"
        if xo == 467:
            return f"mtctr r{rt}"
        if xo == 444:
            return f"or r{ra}, r{rt}, r{rb}"
    if opcode == 21:
        sh = (word >> 11) & 31
        mb = (word >> 6) & 31
        me = (word >> 1) & 31
        return f"rlwinm r{ra}, r{rt}, {sh}, {mb}, {me}"
    return f".long 0x{word:08X}"


def format_function_words(elf: ElfImage, symbol: ElfSymbol, max_words: int | None = None) -> str:
    code = elf.bytes_at(symbol.value, symbol.size)
    lines = [f"{symbol.name} @ 0x{symbol.value:08X}, size 0x{symbol.size:X}"]
    count = len(code) // 4 if max_words is None else min(max_words, len(code) // 4)
    for index in range(count):
        addr = symbol.value + index * 4
        word = struct.unpack_from(">I", code, index * 4)[0]
        lines.append(f"  0x{addr:08X}: {word:08X}  {ppc_mnemonic(addr, word)}")
    return "\n".join(lines)


def format_analysis(elf: ElfImage, include_disasm: bool = True) -> str:
    lines = []
    lines.append(f"ELF: {elf.path}")
    lines.append("")
    lines.append("[sections]")
    for section in elf.sections:
        if section.name in (".text", ".rodata", ".data", ".sdata", ".bss"):
            lines.append(
                f"{section.name}: addr=0x{section.addr:08X} offset=0x{section.offset:08X} size=0x{section.size:X}"
            )
    lines.append("")

    hits = [
        symbol for symbol in elf.symbols
        if any(keyword in symbol.name for keyword in PVM_KEYWORDS)
    ]
    hits.sort(key=lambda item: (item.value, item.name))
    lines.append(f"[PVM-related symbols: {len(hits)}]")
    for symbol in hits:
        lines.append(
            f"0x{symbol.value:08X} size=0x{symbol.size:05X} info=0x{symbol.info:02X} {symbol.name}"
        )
    lines.append("")

    if include_disasm:
        wanted = [
            "GetPVOpSize__FPUc",
            "step__15PVirtualMachineFv",
            "applyOperator__15PVirtualMachineFv",
            "init__14PVLoadedModuleFPC8PVModuleP12PSymbolTableP9PVAdapter",
            "resolveRefs__14PVLoadedModuleFPC8PVModulePPC10ParserTypePUsPP7PSymbolPP9PVariable",
        ]
        lines.append("[selected function words]")
        by_name = {symbol.name: symbol for symbol in elf.symbols}
        for name in wanted:
            symbol = by_name.get(name)
            if not symbol:
                continue
            lines.append(format_function_words(elf, symbol))
            lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def main(argv=None):
    parser = argparse.ArgumentParser(description="Analyze PowerPC ELF symbols relevant to PWK PVM scripts")
    parser.add_argument("elf", type=Path)
    parser.add_argument("-o", "--output", type=Path)
    parser.add_argument("--no-disasm", action="store_true")
    args = parser.parse_args(argv)

    elf = ElfImage(args.elf)
    text = format_analysis(elf, include_disasm=not args.no_disasm)
    if args.output:
        args.output.write_text(text, encoding="utf-8", newline="\n")
        print(f"Wrote ELF analysis: {args.output}")
    else:
        print(text)


if __name__ == "__main__":
    main()
