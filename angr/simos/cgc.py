import logging

import claripy
from cle import BackedCGC

from ..procedures import SIM_LIBRARIES as L
from ..state_plugins import SimActionData
from .. import sim_options as o
from .userland import SimUserland

_l = logging.getLogger(name=__name__)


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
    def state_blank(self, flag_page=None, allocate_stack_page_count=0x100, **kwargs):
        """
        :param flag_page:                   Flag page content, either a string or a list of BV8s
        :param allocate_stack_page_count:   Number of pages to pre-allocate for stack
        """
        # default stack as specified in the cgc abi
        if kwargs.get('stack_end', None) is None:
            kwargs['stack_end'] = 0xbaaab000
        if kwargs.get('stack_size', None) is None:
            kwargs['stack_size'] = 1024*1024*8

        s = super(SimCGC, self).state_blank(**kwargs)  # pylint:disable=invalid-name

        # pre-grow the stack. unsure if this is strictly required or just a hack around a compiler bug
        if hasattr(s.memory, 'allocate_stack_pages'):
            s.memory.allocate_stack_pages(kwargs['stack_end'] - 1, allocate_stack_page_count * 0x1000)

        # Map the flag page
        if o.ABSTRACT_MEMORY not in s.options:
            s.memory.map_region(0x4347c000, 4096, 1)

        # Create the CGC plugin
        s.get_plugin('cgc')

        # Set maximum bytes a single receive syscall should read
        s.cgc.max_receive_size = kwargs.get("cgc_max_recv_size", 0)

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

        # set up the address for concrete transmits and receive
        s.unicorn.cgc_transmit_addr = self.syscall_from_number(2).addr
        s.unicorn.cgc_receive_addr = self.syscall_from_number(3).addr
        s.unicorn.cgc_random_addr = self.syscall_from_number(7).addr

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
