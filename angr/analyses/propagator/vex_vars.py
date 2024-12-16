# VEX Variables
from __future__ import annotations


class VEXVariable:
    __slots__ = ()

    def __hash__(self):
        raise NotImplementedError

    def __eq__(self, other):
        raise NotImplementedError


class VEXMemVar:
    __slots__ = (
        "addr",
        "size",
    )

    def __init__(self, addr: int, size: int):
        self.addr = addr
        self.size = size

    def __hash__(self):
        return hash((VEXMemVar, self.addr, self.size))

    def __eq__(self, other):
        return type(other) is VEXMemVar and other.addr == self.addr and other.size == self.size

    def __repr__(self):
        return f"<mem {self.addr:#x}[{self.size} bytes]>"


class VEXReg(VEXVariable):
    __slots__ = (
        "offset",
        "size",
    )

    def __init__(self, offset, size):
        self.offset = offset
        self.size = size

    def __hash__(self):
        return hash((VEXReg, self.offset, self.size))

    def __eq__(self, other):
        return type(other) is VEXReg and other.offset == self.offset and other.size == self.size

    def __repr__(self):
        return f"<reg {self.offset}[{self.size}]>"


class VEXTmp(VEXVariable):
    __slots__ = ("tmp",)

    def __init__(self, tmp):
        self.tmp = tmp

    def __hash__(self):
        return hash((VEXTmp, self.tmp))

    def __eq__(self, other):
        return type(other) is VEXTmp and other.tmp == self.tmp

    def __repr__(self):
        return f"<tmp {self.tmp}>"
