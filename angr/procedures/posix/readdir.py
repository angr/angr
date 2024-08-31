from __future__ import annotations
import logging
from collections import namedtuple

import claripy

import angr


l = logging.getLogger(name=__name__)

Dirent = namedtuple("dirent", ("d_ino", "d_off", "d_reclen", "d_type", "d_name"))


class readdir(angr.SimProcedure):
    struct = None
    condition = None

    def run(self, dirp):  # pylint: disable=arguments-differ
        # TODO: make sure argument is actually a dir struct
        if self.state.arch.name != "AMD64":
            l.error("readdir SimProcedure is only implemented for AMD64")
            return 0

        self._build_amd64()
        self.instrument()
        malloc = angr.SIM_PROCEDURES["libc"]["malloc"]
        pointer = self.inline_call(malloc, 19 + 256).ret_expr
        self._store_amd64(pointer)
        return claripy.If(self.condition, pointer, 0)

    def instrument(self):
        """
        Override this function to instrument the SimProcedure.

        The two useful variables you can override are self.struct, a named tuple of all the struct
        fields, and self.condition, the condition for whether the function succeeds.
        """

    def _build_amd64(self):
        self.struct = Dirent(
            claripy.BVV(0, 64),  # d_ino
            claripy.BVV(0, 64),  # d_off
            self.state.solver.BVS("d_reclen", 16, key=("api", "readdir", "d_reclen")),  # d_reclen
            self.state.solver.BVS("d_type", 8, key=("api", "readdir", "d_type")),  # d_type
            self.state.solver.BVS("d_name", 255 * 8, key=("api", "readdir", "d_name")),
        )  # d_name
        self.condition = claripy.BoolS("readdir_cond")  # TODO: variable key

    def _store_amd64(self, ptr):
        def stores(offset, val):
            return self.state.memory.store(ptr + offset, val, endness="Iend_BE")

        def storei(offset, val):
            return self.state.memory.store(ptr + offset, val, endness="Iend_LE")

        storei(0, self.struct.d_ino)
        storei(8, self.struct.d_off)
        storei(16, self.struct.d_reclen)
        storei(18, self.struct.d_type)
        stores(19, self.struct.d_name)
        stores(19 + 255, claripy.BVV(0, 8))
