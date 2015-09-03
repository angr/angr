import os
import re
from .plugin import SimStatePlugin
from ..s_errors import SimStateError
import libc as libc
import logging
import claripy
import binascii

l = logging.getLogger('simuvex.plugins.gdb')

#global heap_location

class GDB(SimStatePlugin):
    """
        Initializes/updates a state from gdb dumps of the stack, heap, registers
        and data (or arbitrary) segments.
    """

    def __init__(self, omit_fp=False, adjust_stack=True):
        SimStatePlugin.__init__(self)

        # our stack_top - gdb sessions's
        self.real_stack_top = 0
        self.real_heap = 0
        # Is the binary compiled with --omit_frame_pointer ?
        self.omit_fp = omit_fp
        # Adjust the stack w.r.t. the real stack (from the gdb session)
        self.adjust_stack = adjust_stack

    def set_stack(self, stack_dump, real_stack_top):
        """
        Stack dump is a dump of the stack from gdb, i.e. the result of the
        following gdb command:
        dump binary memory [stack_dump] [begin_addr] [end_addr]"
        where:
            @stack_dump is the dump file

        @real_stack_top is the address of the top of the stack in the gdb session.
        """

        # Our stack top
        stack_top = self.state.arch.initial_sp
        # In Gdb session
        self.real_stack_top = real_stack_top

        data = self._read_data(stack_dump)
        addr = stack_top - len(data) # Address of the bottom of the stack
        #self.state.memory.store(addr, self._to_bvv(data))
        l.info("Setting stack from 0x%x up to 0x%x" % (addr, stack_top))
        self._write(addr, data)

    def set_heap(self, heap_dump, real_heap):
        """
        Heap dump is a dump of the heap from gdb, i.e. the result of the
        following gdb command:
        dump binary memory [stack_dump] [begin] [end]"
        where:
            - heap_dump is the dump file
            - begin is the begin of the heap
            - end is the end of the heap
        @real_heap is the start address of the real heap (from gdb)
        """
        self.real_heap = real_heap
        data = self._read_data(heap_dump)
        addr = libc.heap_location
        l.info("Set heap from 0x%x to 0x%x" % (addr, addr+len(data)))
        self._write(addr, data)

    def set_data(self, addr, data_dump):
        """
        Update any data range (most likely use is the data segments of loaded
        objects)
        """
        data = self._read_data(data_dump)
        l.info("Set heap from 0x%x to 0x%x" % (addr, addr+len(data)))
        self._write(addr, data)

    def set_regs(self, regs_dump):
        """
        Initialize register values within the state
        @regs_dumo is the output of `info registers` from within gdb
        @omit_frame_pointer: is the frame pointer register actually used as is,
        or used for something else (optimization) ?
        """

        if self.real_stack_top == 0 and self.adjust_stack is True:
            raise SimStateError("You need to set the stack first, or set"
                    "adjust_stack to False. Beware that in this case, sp and bp won't be updated")

        data = self._read_data(regs_dump)
        rdata = re.split("\n", data)
        for r in rdata:
            if r == "":
                continue
            reg = re.split(" +", r)[0]
            val = int(re.split(" +", r)[1],16)
            try:
                self.state.registers.store(reg, claripy.BVV(val, self.state.arch.bits))
            # Some registers such as cs, ds, eflags etc. aren't supported in Angr
            except KeyError as e:
                l.warning("Reg %s was not set" % str(e))

        self._adjust_regs()

    def _adjust_regs(self):
        """
        Adjust bp and sp w.r.t. stack difference between GDB session and Angr.
        """
        if not self.adjust_stack:
            return

        bp = self.state.arch.register_names[self.state.arch.bp_offset]
        sp = self.state.arch.register_names[self.state.arch.sp_offset]

        stack_shift = self.state.arch.initial_sp - self.real_stack_top
        self.state.registers.store(sp, self.state.regs.sp.model.value + stack_shift)

        if not self.omit_fp:
            self.state.registers.store(bp, self.state.regs.bp.model.value + stack_shift)

    def _read_data(self, path):
        if not os.path.exists(path):
            raise SimStateError("File does not exist")
        f = open(path, "rb")
        return f.read()

    def _write(self, addr, data):
        for d in data:
            self.state.memory.store(addr, d, size=1)
            addr = addr + 1

    def _to_bvv(self, data):
        sz = len(data)
        num = int(binascii.hexlify(data), 16)
        return claripy.BVV(num, sz)

SimStatePlugin.register_default('gdb', GDB)
