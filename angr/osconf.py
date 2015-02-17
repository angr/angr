"""
Manage OS-level configuration
"""

import pyvex

from simuvex import SimState
from simuvex.s_arch import SimARM, SimMIPS32, SimX86, SimAMD64
from simuvex import s_options

class OSConf(object):
    """A class describing OS/arch-level configuration"""

    def __init__(self, arch):
        self.arch = arch

    def configure_project(self, proj):
        """Configure the project to set up global settings (like SimProcedures)"""
        pass

    def make_state(self, **kwargs):
        """Create an initial state"""
        initial_prefix = kwargs.pop("initial_prefix", None)

        state = SimState(arch=self.arch, **kwargs)
        state.store_reg(self.arch.sp_offset, self.arch.initial_sp, self.arch.bits / 8)

        if initial_prefix is not None:
            for reg in self.arch.default_symbolic_registers:
                state.store_reg(reg, state.se.Unconstrained(initial_prefix + "_" + reg,
                                                            self.arch.bits,
                                                            explicit_name=True))

        for reg, val, is_addr, mem_region in self.arch.default_register_values:
            if s_options.ABSTRACT_MEMORY in state.options and is_addr:
                addr = state.se.ValueSet(region=mem_region, bits=self.arch.bits, val=val)
                state.store_reg(reg, addr)
            else:
                state.store_reg(reg, val)

        return state

    def prepare_call_state(self, calling_state, initial_state=None,
                           preserve_registers=(), preserve_memory=()):
        '''
        This function prepares a state that is executing a call instruction.
        If given an initial_state, it copies over all of the critical registers to it from the
        calling_state. Otherwise, it prepares the calling_state for action.

        This is mostly used to create minimalistic for CFG generation. Some ABIs, such as MIPS PIE and
        x86 PIE, require certain information to be maintained in certain registers. For example, for
        PIE MIPS, this function transfer t9, gp, and ra to the new state.
        '''

        if isinstance(self.arch, SimMIPS32):
            if initial_state is not None:
                initial_state = self.make_state()
            mips_caller_saves = ('s0', 's1', 's2', 's3', 's4', 's5', 's6', 's7', 'gp', 'sp', 'bp', 'ra')
            preserve_registers = preserve_registers + mips_caller_saves + ('t9',)

        if initial_state is None:
            new_state = calling_state.copy()
        else:
            new_state = initial_state.copy()
            for reg in set(preserve_registers):
                new_state.store_reg(reg, calling_state.reg_expr(reg))
            for addr, val in set(preserve_memory):
                new_state.store_mem(addr, calling_state.mem_expr(addr, val))

        return new_state

class LinuxConf(OSConf): # no, not a conference...
    """OS-specific configuration for Linux"""
    def configure_project(self, proj):
        if isinstance(self.arch, SimARM):
            # set up kernel-user helpers
            pass

    def make_state(self, **kwargs):
        s = super(LinuxConf, self).make_state(**kwargs) #pylint:disable=invalid-name

        if isinstance(self.arch, SimX86):
            # untested :)
            thread_addr = 0x90000000
            dtv_entry = 0x15000000 # let's hope there's nothing here...
            dtv_base = 0x16000000 # same

            s.store_reg('gs', s.se.BVV(thread_addr >> 16, 16))

            s.store_mem(dtv_base + 0x00, s.se.BVV(dtv_entry, 32), endness='Iend_LE')
            s.store_mem(dtv_base + 0x04, s.se.BVV(1, 8))

            s.store_mem(thread_addr + 0x00, s.se.BVV(thread_addr, 32), endness='Iend_LE') # tcb
            s.store_mem(thread_addr + 0x04, s.se.BVV(dtv_base, 32), endness='Iend_LE') # dtv
            s.store_mem(thread_addr + 0x08, s.se.BVV(0x12345678, 32)) # self
            s.store_mem(thread_addr + 0x0c, s.se.BVV(0x1, 32), endness='Iend_LE') # multiple_threads
        elif isinstance(self.arch, SimAMD64):
            dtv_entry = 0xff000000000
            dtv_base = 0x8000000000000000

            s.store_reg('fs', 0x9000000000000000)

            s.store_mem(dtv_base + 0x00, s.se.BVV(dtv_entry, 64), endness='Iend_LE')
            s.store_mem(dtv_base + 0x08, s.se.BVV(1, 8))

            s.store_mem(s.reg_expr('fs') + 0x00, s.reg_expr('fs'), endness='Iend_LE') # tcb
            s.store_mem(s.reg_expr('fs') + 0x08, s.se.BVV(dtv_base, 64), endness='Iend_LE') # dtv
            s.store_mem(s.reg_expr('fs') + 0x10, s.se.BVV(0x12345678, 64)) # self
            s.store_mem(s.reg_expr('fs') + 0x18, s.se.BVV(0x1, 32), endness='Iend_LE') # multiple_threads

        return s

