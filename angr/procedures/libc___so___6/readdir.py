import simuvex
from collections import namedtuple

from .malloc import malloc

import logging
l = logging.getLogger('simuvex.procedures.libc___so___6.readdir')

Dirent = namedtuple('dirent', ('d_ino', 'd_off', 'd_reclen', 'd_type', 'd_name'))

class readdir(simuvex.SimProcedure):
    struct = None
    condition = None

    def run(self, dirp): # pylint: disable=arguments-differ
        # TODO: make sure argument is actually a dir struct
        if self.state.arch.name != 'AMD64':
            l.error('readdir SimProcedure is only implemented for AMD64')
            return 0

        self._build_amd64()
        self.instrument()
        pointer = self.inline_call(malloc, 19 + 256).ret_expr
        self._store_amd64(pointer)
        return self.state.se.If(self.condition, pointer, self.state.se.BVV(0, len(pointer)))

    def instrument(self):
        pass # override me!

    def _build_amd64(self):
        self.struct = Dirent(self.state.se.BVV(0, 64), # d_ino
                             self.state.se.BVV(0, 64), # d_off
                             self.state.se.BVS('d_reclen', 16), # d_reclen
                             self.state.se.BVS('d_type', 8), # d_type
                             self.state.se.BVS('d_name', 255*8)) # d_name
        self.condition = self.state.se.BoolS('readdir_cond')

    def _store_amd64(self, ptr):
        stores = lambda offset, val: self.state.memory.store(ptr + offset, val, endness='Iend_BE')
        storei = lambda offset, val: self.state.memory.store(ptr + offset, val, endness='Iend_LE')

        storei(0, self.struct.d_ino)
        storei(8, self.struct.d_off)
        storei(16, self.struct.d_reclen)
        storei(18, self.struct.d_type)
        stores(19, self.struct.d_name)
        stores(19+255, self.state.se.BVV(0, 8))
