
import logging

import claripy
from cle import BackedCGC

from ..misc import IRange
from ..procedures import SIM_LIBRARIES as L
from ..state_plugins import SimActionData
from .. import sim_options as o
from .userland import SimUserland

_l = logging.getLogger('angr.simos.cgc')


class SimCGC(SimUserland):
    """
    Environment configuration for the CGC DECREE platform
    """

    def __init__(self, project, **kwargs):
        super(SimCGC, self).__init__(project,
                syscall_library=L['cgcabi'],
                syscall_addr_alignment=1,
                name="CGC",
                **kwargs)

    # pylint: disable=arguments-differ
    def state_blank(self, flag_page=None, **kwargs):
        """
        :param flag_page:   Flag page content, either a string or a list of BV8s
        """
        s = super(SimCGC, self).state_blank(**kwargs)  # pylint:disable=invalid-name

        # Special stack base for CGC binaries to work with Shellphish CRS
        s.regs.sp = 0xbaaaaffc

        # Map the special cgc memory
        if o.ABSTRACT_MEMORY not in s.options:
            s.memory.mem._preapproved_stack = IRange(0xbaaab000 - 1024 * 1024 * 8, 0xbaaab000)
            s.memory.map_region(0x4347c000, 4096, 1)

        # Create the CGC plugin
        s.get_plugin('cgc')

        # Set up the flag page
        if flag_page is None:
            flag_page = [s.solver.BVS("cgc-flag-byte-%d" % i, 8, key=('flag', i), eternal=True) for i in range(0x1000)]
        elif type(flag_page) is bytes:
            flag_page = [s.solver.BVV(c, 8) for c in flag_page]
        elif type(flag_page) is list:
            pass
        else:
            raise ValueError("Bad flag page: expected None, bytestring, or list, but got %s" % type(flag_page))

        s.cgc.flag_bytes = flag_page
        if s.mode != 'static':
            s.memory.store(0x4347c000, claripy.Concat(*s.cgc.flag_bytes), priv=True)

        # set up the address for concrete transmits
        s.unicorn.transmit_addr = self.syscall_from_number(2).addr

        s.libc.max_str_len = 1000000
        s.libc.max_strtol_len = 10
        s.libc.max_memcpy_size = 0x100000
        s.libc.max_buffer_size = 0x100000

        return s

    def state_entry(self, add_options=None, **kwargs):
        if isinstance(self.project.loader.main_object, BackedCGC):
            kwargs['permissions_backer'] = (True, self.project.loader.main_object.permissions_map)
        if add_options is None:
            add_options = set()
        add_options.add(o.ZERO_FILL_UNCONSTRAINED_MEMORY)

        state = super(SimCGC, self).state_entry(add_options=add_options, **kwargs)

        if isinstance(self.project.loader.main_object, BackedCGC):
            for reg, val in self.project.loader.main_object.initial_register_values():
                if reg in state.arch.registers:
                    setattr(state.regs, reg, val)
                elif reg == 'eflags':
                    pass
                elif reg == 'fctrl':
                    state.regs.fpround = (val & 0xC00) >> 10
                elif reg == 'fstat':
                    state.regs.fc3210 = (val & 0x4700)
                elif reg == 'ftag':
                    empty_bools = [((val >> (x * 2)) & 3) == 3 for x in range(8)]
                    tag_chars = [claripy.BVV(0 if x else 1, 8) for x in empty_bools]
                    for i, tag in enumerate(tag_chars):
                        setattr(state.regs, 'fpu_t%d' % i, tag)
                elif reg in ('fiseg', 'fioff', 'foseg', 'fooff', 'fop'):
                    pass
                elif reg == 'mxcsr':
                    state.regs.sseround = (val & 0x600) >> 9
                else:
                    _l.error("What is this register %s I have to translate?", reg)

            # Update allocation base
            state.cgc.allocation_base = self.project.loader.main_object.current_allocation_base

            # Do all the writes
            writes_backer = self.project.loader.main_object.writes_backer
            stdout = state.posix.get_fd(1)
            pos = 0
            for size in writes_backer:
                if size == 0:
                    continue
                str_to_write = state.solver.BVS('file_write', size*8)
                a = SimActionData(
                        state,
                        'file_1_0',
                        'write',
                        addr=claripy.BVV(pos, state.arch.bits),
                        data=str_to_write,
                        size=size)
                stdout.write_data(str_to_write)
                state.history.add_action(a)
                pos += size

        else:
            # Set CGC-specific variables
            state.regs.eax = 0
            state.regs.ebx = 0
            state.regs.ecx = 0x4347c000
            state.regs.edx = 0
            state.regs.edi = 0
            state.regs.esi = 0
            state.regs.esp = 0xbaaaaffc
            state.regs.ebp = 0
            state.regs.cc_dep1 = 0x202  # default eflags
            state.regs.cc_op = 0  # OP_COPY
            state.regs.cc_dep2 = 0  # doesn't matter
            state.regs.cc_ndep = 0  # doesn't matter

            # fpu values
            state.regs.mm0 = 0
            state.regs.mm1 = 0
            state.regs.mm2 = 0
            state.regs.mm3 = 0
            state.regs.mm4 = 0
            state.regs.mm5 = 0
            state.regs.mm6 = 0
            state.regs.mm7 = 0
            state.regs.fpu_tags = 0
            state.regs.fpround = 0
            state.regs.fc3210 = 0x0300
            state.regs.ftop = 0

            # sse values
            state.regs.sseround = 0
            state.regs.xmm0 = 0
            state.regs.xmm1 = 0
            state.regs.xmm2 = 0
            state.regs.xmm3 = 0
            state.regs.xmm4 = 0
            state.regs.xmm5 = 0
            state.regs.xmm6 = 0
            state.regs.xmm7 = 0

            # segmentation registers
            state.regs.ds = 0
            state.regs.es = 0
            state.regs.fs = 0
            state.regs.gs = 0
            state.regs.ss = 0
            state.regs.cs = 0

        return state
