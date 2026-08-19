from __future__ import annotations

import struct
from pathlib import Path
from typing import Any


def cstr(data: bytes | bytearray, off: int) -> str:
    end = off
    while end < len(data) and data[end] != 0:
        end += 1
    raw = data[off:end].decode("ascii", errors="ignore")
    return "".join(ch for ch in raw if 32 <= ord(ch) <= 126).strip()


class PipeworksParser:
    """Small read-only Pipeworks BDG parser for PRX tools.

    This intentionally omits GZBuildr's extraction/rebuild/UI code. The PRX
    text tool only needs file names, main/resource offsets, sizes, and the
    shared string table offset.
    """

    def __init__(self, filepath: str | Path):
        self.filepath = str(filepath)
        self.file_data: bytes = b""
        self.is_big_endian = False
        self.string_offset = 0
        self.file_count = 0
        self.metadata_offset = 0
        self.main_data_offset = 0
        self.resource_data_offset = 0

    @property
    def endian(self) -> str:
        return ">" if self.is_big_endian else "<"

    def read_byte(self, offset: int) -> int:
        return self.file_data[offset]

    def read_short(self, offset: int) -> int:
        return struct.unpack_from(f"{self.endian}H", self.file_data, offset)[0]

    def read_long(self, offset: int) -> int:
        return struct.unpack_from(f"{self.endian}I", self.file_data, offset)[0]

    def read_long_little(self, offset: int) -> int:
        return struct.unpack_from("<I", self.file_data, offset)[0]

    def read_bytes(self, offset: int, size: int) -> bytes:
        return self.file_data[offset : offset + size]

    def parse(self) -> list[dict[str, Any]]:
        return self.parse_from_data(Path(self.filepath).read_bytes())

    def parse_from_data(self, data: bytes | bytearray) -> list[dict[str, Any]]:
        self.file_data = bytes(data)
        if len(self.file_data) < 0x80:
            raise ValueError("BDG is too small")
        if self.file_data[:9].decode("ascii", errors="ignore") != "Pipeworks":
            raise ValueError("Not a Pipeworks BDG")

        endian_check = struct.unpack_from("<H", self.file_data, 0x2C)[0]
        self.is_big_endian = endian_check == 0

        self.string_offset = self.read_long(0x34)
        self.file_count = self.read_short(0x62)
        self.metadata_offset = self.read_long(0x64)
        self.main_data_offset = self.read_long(0x68)
        self.resource_data_offset = self.read_long(0x70)

        self._validate_header()

        entries: list[dict[str, Any]] = []
        toc_offset = 0x78
        for i in range(self.file_count):
            entry_offset = toc_offset + i * 0x12
            if entry_offset + 0x12 > len(self.file_data):
                raise ValueError("BDG TOC extends past end of file")

            file_num = self.read_short(entry_offset)
            raw_offset = self.read_long(entry_offset + 2)
            size = self.read_long(entry_offset + 6)
            raw_res_offset = self.read_long(entry_offset + 10)
            res_size = self.read_long(entry_offset + 14)
            name, file_type, metadata_bytes = self.get_file_info(file_num)

            entries.append(
                {
                    "file_num": file_num,
                    "name": name,
                    "offset": self.main_data_offset + raw_offset,
                    "size": size,
                    "raw_offset": raw_offset,
                    "toc_entry_offset": entry_offset,
                    "is_resource": False,
                    "file_type": file_type,
                    "metadata_bytes": metadata_bytes,
                }
            )

            if res_size > 0:
                entries.append(
                    {
                        "file_num": file_num,
                        "name": f"{name}.resource",
                        "offset": self.resource_data_offset + raw_res_offset,
                        "size": res_size,
                        "raw_offset": raw_res_offset,
                        "toc_entry_offset": entry_offset,
                        "is_resource": True,
                        "file_type": file_type,
                        "metadata_bytes": metadata_bytes,
                    }
                )

        return entries

    def get_file_info(self, file_num: int) -> tuple[str, int, bytes]:
        metadata_start = self.metadata_offset + file_num * 0x10
        if metadata_start + 0x10 > len(self.file_data):
            raise ValueError(f"Metadata entry {file_num} extends past end of file")

        entry_offset = metadata_start + 0x2
        file_type = self.read_byte(entry_offset)
        string_id = self.read_long(entry_offset + 2)
        string_offset_pos = self.string_offset + 4 + string_id * 4
        if string_offset_pos + 4 > self.metadata_offset:
            raise ValueError(f"String id {string_id} is outside the string table")

        rel_string_offset = self.read_long_little(string_offset_pos)
        string_pos = self.string_offset + rel_string_offset
        if not (self.string_offset <= string_pos < self.metadata_offset):
            raise ValueError(f"String id {string_id} points outside the string table")

        name = cstr(self.file_data, string_pos) or f"file_{file_num}"
        clean_name = name.replace("|", "_")
        metadata_bytes = self.read_bytes(metadata_start, 0x10)
        return f"{file_type}/{clean_name}", file_type, metadata_bytes

    def read_strings(self) -> list[str]:
        count = struct.unpack_from("<I", self.file_data, self.string_offset)[0]
        strings: list[str] = []
        for idx in range(count):
            rel = struct.unpack_from("<I", self.file_data, self.string_offset + 4 + idx * 4)[0]
            pos = self.string_offset + rel
            if not (self.string_offset <= pos < self.metadata_offset):
                strings.append("")
                continue
            strings.append(cstr(self.file_data, pos))
        return strings

    def _validate_header(self) -> None:
        if self.file_count <= 0:
            raise ValueError("BDG file count is zero")
        offsets = [
            ("string table", self.string_offset),
            ("metadata table", self.metadata_offset),
            ("main data", self.main_data_offset),
            ("resource data", self.resource_data_offset),
        ]
        for label, offset in offsets:
            if not (0 < offset <= len(self.file_data)):
                raise ValueError(f"Invalid {label} offset 0x{offset:X}")
        if not (0x78 < self.string_offset <= self.metadata_offset <= self.main_data_offset):
            raise ValueError("BDG header offsets are not in expected order")
