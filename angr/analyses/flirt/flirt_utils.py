# Util functions that are mostly rewrite of the original code in redare2
from __future__ import annotations
import struct


def read_short(file_obj) -> int:
    return struct.unpack(">H", file_obj.read(2))[0]


def read_word(file_obj) -> int:
    return struct.unpack(">I", file_obj.read(4))[0]


def read_max_2_bytes(file_obj) -> int:
    b = file_obj.read(1)[0]
    if b & 0x80 != 0x80:
        return b
    return ((b & 0x7F) << 8) + file_obj.read(1)[0]


def read_multiple_bytes(file_obj) -> int:
    b = file_obj.read(1)[0]
    if b & 0x80 != 0x80:
        return b
    if b & 0xC0 != 0xC0:
        return ((b & 0x7F) << 8) + file_obj.read(1)[0]
    if b & 0xE0 != 0xE0:
        b = ((b & 0x3F) << 24) + (file_obj.read(1)[0] << 16)
        b += read_short(file_obj)
        return b
    return read_word(file_obj)
