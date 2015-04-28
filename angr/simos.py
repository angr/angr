"""
Manage OS-level configuration
"""

import logging
l = logging.getLogger("angr.simos")

from simuvex import SimState
from simuvex.s_arch import SimARM, SimMIPS32, SimX86, SimAMD64
from simuvex import s_options
from simuvex.s_type import SimTypePointer, SimTypeFunction, SimTypeTop
from simuvex import SimProcedure

class SimOS(object):
    """A class describing OS/arch-level configuration"""

    def __init__(self, arch, project):
        self.arch = arch
        self.proj = project

    def configure_project(self, proj):
        """Configure the project to set up global settings (like SimProcedures)"""
        pass

    def make_state(self, **kwargs):
        """Create an initial state"""
        initial_prefix = kwargs.pop("initial_prefix", None)

        state = SimState(arch=self.arch, **kwargs)
        state.regs.sp = self.arch.initial_sp

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

class SimPosix(SimOS):
    """OS-specific configuration for POSIX-y OSes"""
    def configure_project(self, proj):
        super(SimPosix, self).configure_project(proj)
        if isinstance(proj.arch, SimAMD64):
            setup_elf_ifuncs(proj)

    def make_state(self, **kwargs):
        s = super(SimPosix, self).make_state(**kwargs) #pylint:disable=invalid-name
        s = setup_elf_tls(self.proj, s)

        return s

class SimLinux(SimPosix): # no, not a conference...
    """OS-specific configuration for Linux"""
    def configure_project(self, proj):
        super(SimLinux, self).configure_project(proj)
        if isinstance(self.arch, SimARM):
            # set up kernel-user helpers
            pass

    def make_state(self, **kwargs):
        s = super(SimLinux, self).make_state(**kwargs) #pylint:disable=invalid-name

        return s

def setup_elf_tls(proj, s):
    if isinstance(s.arch, SimAMD64):
        tls_addr = 0x16000000
        for mod_id, so in enumerate(proj.ld.shared_objects):
            for i, byte in enumerate(so.tls_init_image):
                s.store_mem(tls_addr + i, s.se.BVV(ord(byte), 8))
            s.posix.tls_modules[mod_id] = tls_addr
            tls_addr += len(so.tls_init_image)

        dtv_entry = 0xff000000000
        dtv_base = 0x8000000000000000

        s.regs.fs = 0x9000000000000000

        s.store_mem(dtv_base + 0x00, s.se.BVV(dtv_entry, 64), endness='Iend_LE')
        s.store_mem(dtv_base + 0x08, s.se.BVV(1, 8))

        s.store_mem(s.regs.fs + 0x00, s.regs.fs, endness='Iend_LE') # tcb
        s.store_mem(s.regs.fs + 0x08, s.se.BVV(dtv_base, 64), endness='Iend_LE') # dtv
        s.store_mem(s.regs.fs + 0x10, s.se.BVV(0x12345678, 64)) # self
        s.store_mem(s.regs.fs + 0x18, s.se.BVV(0x1, 32), endness='Iend_LE') # multiple_threads
        s.store_mem(s.regs.fs + 0x28, s.se.BVV(0x5f43414e4152595f, 64), endness='Iend_LE')
    elif isinstance(s.arch, SimX86):
        # untested :)
        thread_addr = 0x90000000
        dtv_entry = 0x15000000 # let's hope there's nothing here...
        dtv_base = 0x16000000 # same

        s.regs.gs = s.se.BVV(thread_addr >> 16, 16)

        s.store_mem(dtv_base + 0x00, s.se.BVV(dtv_entry, 32), endness='Iend_LE')
        s.store_mem(dtv_base + 0x04, s.se.BVV(1, 8))

        s.store_mem(thread_addr + 0x00, s.se.BVV(thread_addr, 32), endness='Iend_LE') # tcb
        s.store_mem(thread_addr + 0x04, s.se.BVV(dtv_base, 32), endness='Iend_LE') # dtv
        s.store_mem(thread_addr + 0x08, s.se.BVV(0x12345678, 32)) # self
        s.store_mem(thread_addr + 0x0c, s.se.BVV(0x1, 32), endness='Iend_LE') # multiple_threads
    return s

def setup_elf_ifuncs(proj):
    for binary in [proj.ld.main_bin] + proj.ld.shared_objects:
        for reloc in binary.relocs:
            if reloc.symbol is None or reloc.resolvedby is None:
                continue
            if reloc.resolvedby.type != 'STT_GNU_IFUNC':
                continue
            gotaddr = reloc.addr + binary.rebase_addr
            gotvalue = proj.ld.memory.read_addr_at(gotaddr)
            if proj.is_sim_procedure(gotvalue):
                continue
            # Replace it with a ifunc-resolve simprocedure!
            resolver = make_ifunc_resolver(proj, gotvalue, gotaddr, reloc.symbol.name)
            randaddr = int(hash(('ifunc', gotvalue, gotaddr)) % 2**proj.arch.bits)
            proj.add_custom_sim_procedure(randaddr, resolver)
            proj.ld.memory.write_addr_at(gotaddr, randaddr)

def make_ifunc_resolver(proj, funcaddr, gotaddr, funcname):
    class IFuncResolver(SimProcedure):
        def run(self):
            resolve = Callable(proj, funcaddr, SimTypeFunction((), SimTypePointer(self.state.arch, SimTypeTop())))
            value = resolve()
            self.state.store_mem(gotaddr, value, endness=self.state.arch.memory_endness)
            self.add_successor(self.state, value, self.state.se.true, 'Ijk_Boring')

        def __repr__(self):
            return '<IFuncResolver %s>' % funcname
    return IFuncResolver

from .surveyors.caller import Callable

class CGCConf(SimOS):
    def __init__(self, proj):
        arch = SimX86()
        SimOS.__init__(self, arch, proj)

    def make_state(self, **kwargs):
        s = super(CGCConf, self).make_state(**kwargs)  # pylint:disable=invalid-name

        # Create the CGC plugin
        s.get_plugin('cgc')

        return s
