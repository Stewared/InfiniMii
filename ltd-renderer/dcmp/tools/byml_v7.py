#!/usr/bin/env python3
"""Bounds-checked reader for the little-endian BYML v7 nodes used by the title."""

from __future__ import annotations

import struct
from pathlib import Path
from typing import Any


class LittleEndianBymlV7:
    """Decode a little-endian (``YB``) BYML v7 document without schema guesses."""

    PLAIN_HASH = 0x20
    ARRAY = 0xC0
    STRING_DICTIONARY = 0xC1
    STRING_TABLE = 0xC2
    STRING = 0xA0
    BOOL = 0xD0
    INT = 0xD1
    FLOAT = 0xD2
    UINT = 0xD3
    INT64 = 0xD4
    UINT64 = 0xD5
    DOUBLE = 0xD6
    NULL = 0xFF

    def __init__(self, path: Path):
        self.path = path
        self.data = path.read_bytes()
        if len(self.data) < 16 or self.data[:2] != b"YB" or self._u16(2) != 7:
            raise ValueError(f"{path} is not little-endian BYML v7")
        self.key_table_offset, self.string_table_offset, self.root_offset = (
            struct.unpack_from("<III", self.data, 4)
        )
        self.keys = self._decode_string_table(self.key_table_offset)
        self.strings = self._decode_string_table(self.string_table_offset)
        self._decoded_containers: dict[int, Any] = {}
        self._active_container_offsets: set[int] = set()

    def _require_bounds(self, offset: int, size: int) -> None:
        if offset < 0 or size < 0 or offset + size > len(self.data):
            raise ValueError(f"BYML read outside {self.path}: {offset:#x}+{size:#x}")

    def _u16(self, offset: int) -> int:
        self._require_bounds(offset, 2)
        return struct.unpack_from("<H", self.data, offset)[0]

    def _u24(self, offset: int) -> int:
        self._require_bounds(offset, 3)
        return (
            self.data[offset]
            | self.data[offset + 1] << 8
            | self.data[offset + 2] << 16
        )

    def _u32(self, offset: int) -> int:
        self._require_bounds(offset, 4)
        return struct.unpack_from("<I", self.data, offset)[0]

    def _decode_string_table(self, offset: int) -> list[str]:
        self._require_bounds(offset, 4)
        if self.data[offset] != self.STRING_TABLE:
            raise ValueError(f"expected BYML string table at {offset:#x}")
        count = self._u24(offset + 1)
        self._require_bounds(offset + 4, (count + 1) * 4)
        relative_offsets = [
            self._u32(offset + 4 + index * 4) for index in range(count + 1)
        ]
        if relative_offsets != sorted(relative_offsets):
            raise ValueError(f"non-monotonic BYML string offsets at {offset:#x}")
        values: list[str] = []
        for start, end in zip(relative_offsets[:-1], relative_offsets[1:], strict=True):
            self._require_bounds(offset + start, end - start)
            encoded = self.data[offset + start : offset + end]
            if not encoded.endswith(b"\0"):
                raise ValueError(f"unterminated BYML string at {offset + start:#x}")
            values.append(encoded.rstrip(b"\0").decode("utf-8"))
        return values

    def _decode_storage_value(self, node_type: int, raw_value: int) -> Any:
        if node_type == self.STRING:
            if raw_value >= len(self.strings):
                raise ValueError(f"BYML string index {raw_value} out of range")
            return self.strings[raw_value]
        if node_type == self.BOOL:
            if raw_value not in (0, 1):
                raise ValueError(f"invalid BYML bool storage value {raw_value:#x}")
            return bool(raw_value)
        if node_type == self.INT:
            return struct.unpack("<i", struct.pack("<I", raw_value))[0]
        if node_type == self.FLOAT:
            return struct.unpack("<f", struct.pack("<I", raw_value))[0]
        if node_type == self.UINT:
            return raw_value
        if node_type == self.INT64:
            self._require_bounds(raw_value, 8)
            return struct.unpack_from("<q", self.data, raw_value)[0]
        if node_type == self.UINT64:
            self._require_bounds(raw_value, 8)
            return struct.unpack_from("<Q", self.data, raw_value)[0]
        if node_type == self.DOUBLE:
            self._require_bounds(raw_value, 8)
            return struct.unpack_from("<d", self.data, raw_value)[0]
        if node_type == self.NULL:
            return None
        if node_type in (self.PLAIN_HASH, self.ARRAY, self.STRING_DICTIONARY):
            return self._decode_container(raw_value, expected_type=node_type)
        raise ValueError(f"unsupported BYML v7 node type {node_type:#x}")

    def _decode_array(self, offset: int) -> list[Any]:
        count = self._u24(offset + 1)
        node_types_offset = offset + 4
        values_offset = (node_types_offset + count + 3) & ~3
        self._require_bounds(node_types_offset, count)
        self._require_bounds(values_offset, count * 4)
        return [
            self._decode_storage_value(
                self.data[node_types_offset + index],
                self._u32(values_offset + index * 4),
            )
            for index in range(count)
        ]

    def _decode_string_dictionary(self, offset: int) -> dict[str, Any]:
        count = self._u24(offset + 1)
        self._require_bounds(offset + 4, count * 8)
        result: dict[str, Any] = {}
        for index in range(count):
            entry_offset = offset + 4 + index * 8
            key_index = self._u24(entry_offset)
            if key_index >= len(self.keys):
                raise ValueError(f"BYML key index {key_index} out of range")
            key = self.keys[key_index]
            if key in result:
                raise ValueError(f"duplicate BYML dictionary key {key!r} at {offset:#x}")
            result[key] = self._decode_storage_value(
                self.data[entry_offset + 3], self._u32(entry_offset + 4)
            )
        return result

    def _decode_plain_hash(self, offset: int) -> dict[str, Any]:
        """Decode v7 node 0x20: N (u32 hash, u32 value) pairs plus N type bytes."""

        count = self._u24(offset + 1)
        entries_offset = offset + 4
        node_types_offset = entries_offset + count * 8
        self._require_bounds(entries_offset, count * 8)
        self._require_bounds(node_types_offset, count)
        result: dict[str, Any] = {}
        for index in range(count):
            entry_offset = entries_offset + index * 8
            key = f"0x{self._u32(entry_offset):08x}"
            if key in result:
                raise ValueError(f"duplicate BYML plain-hash key {key} at {offset:#x}")
            result[key] = self._decode_storage_value(
                self.data[node_types_offset + index], self._u32(entry_offset + 4)
            )
        return result

    def _decode_container(self, offset: int, expected_type: int | None = None) -> Any:
        self._require_bounds(offset, 4)
        node_type = self.data[offset]
        if expected_type is not None and node_type != expected_type:
            raise ValueError(
                f"BYML node at {offset:#x} has type {node_type:#x}, expected {expected_type:#x}"
            )
        if offset in self._decoded_containers:
            return self._decoded_containers[offset]
        if offset in self._active_container_offsets:
            raise ValueError(f"cyclic BYML container reference at {offset:#x}")
        self._active_container_offsets.add(offset)
        try:
            if node_type == self.ARRAY:
                decoded = self._decode_array(offset)
            elif node_type == self.STRING_DICTIONARY:
                decoded = self._decode_string_dictionary(offset)
            elif node_type == self.PLAIN_HASH:
                decoded = self._decode_plain_hash(offset)
            else:
                raise ValueError(f"unsupported BYML v7 container type {node_type:#x}")
            self._decoded_containers[offset] = decoded
            return decoded
        finally:
            self._active_container_offsets.remove(offset)

    def root(self) -> Any:
        """Return the fully decoded root container."""

        return self._decode_container(self.root_offset)


def decode_little_endian_byml_v7(path: Path) -> Any:
    """Decode one little-endian BYML v7 file."""

    return LittleEndianBymlV7(path).root()
