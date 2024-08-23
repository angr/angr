from __future__ import annotations
import claripy

from ..libc import memset


class bzero(memset.memset):
    def run(self, addr, size):
        return super().run(addr, claripy.BVV(0, self.arch.byte_width), size)
