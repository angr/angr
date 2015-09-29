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

    def __init__(self, omit_fp=False, adjust_stack=False):
        """
        @omit_fp: the frame pointer register is used for something else
        (i.e., --omit_frame_pointer)
        @adjust_stack: use different stack addresses than the gdb session (not recommended)
        """
        SimStatePlugin.__init__(self)

        # The stack top from gdb's session
        self.real_stack_top = 0
        # Is the binary compiled with --omit_frame_pointer ?
        self.omit_fp = omit_fp
        # Adjust the stack w.r.t. the real stack (from the gdb session)
        self.adjust_stack = adjust_stack

    def set_stack(self, stack_dump, stack_top):
        """
        Stack dump is a dump of the stack from gdb, i.e. the result of the
        following gdb command:
        dump binary memory [stack_dump] [begin_addr] [end_addr]"
        where @stack_dump is the dump file.
        @stack_top is the address of the top of the stack in the gdb session.

        We set the stack to the same addresses as the gdb session to avoid
        pointers corruption.
        """
        data = self._read_data(stack_dump)
        self.real_stack_top = stack_top
        addr = stack_top - len(data) # Address of the bottom of the stack
        l.info("Setting stack from 0x%x up to 0x%x" % (addr, stack_top))
        #FIXME: we should probably make we don't overwrite other stuff loaded there
        self._write(addr, data)

    def set_heap(self, heap_dump, heap_base):
        """
        Heap dump is a dump of the heap from gdb, i.e. the result of the
        following gdb command:
        dump binary memory [stack_dump] [begin] [end]"
        where @heap_dump is the dump file.
        @heap_base is the start address of the heap in the gdb session.

        We set the heap at the same addresses as the gdb session to avoid
        pointer corruption.
        """
        data = self._read_data(heap_dump)
        self.state.libc.heap_location = heap_base + len(data)
        addr = heap_base
        l.info("Set heap from 0x%x to 0x%x" % (addr, addr+len(data)))
        #FIXME: we should probably make we don't overwrite other stuff loaded there
        self._write(addr, data)

    def set_data(self, addr, data_dump):
        """
        Update any data range (most likely use is the data segments of loaded
        objects)
        """
        data = self._read_data(data_dump)
        l.info("Set data from 0x%x to 0x%x" % (addr, addr+len(data)))
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
        This matches sp and bp registers, but there is a high risk of pointers
        inconsistencies.
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

    def copy(self):
        return GDB()

SimStatePlugin.register_default('gdb', GDB)
