from .tablespecs import StringTableSpec
from cle.backedcgc import BackedCGC

import simuvex
import logging
l = logging.getLogger('angr.states')

class StateGenerator(object):
    def __init__(self, project):
        self._project = project
        self._arch = project.arch
        self._simos = project.simos
        self._ld = project.ld

    def blank_state(self, mode=None, address=None, initial_prefix=None,
                    options=None, add_options=None, remove_options=None,
                    fs=None):

        if address is None:
            address = self._project.entry
        if mode is None:
            mode = self._project.default_analysis_mode

        memory_backer = self._ld.memory

        state = self._simos.make_state(memory_backer=memory_backer,
                                       mode=mode, options=options,
                                       initial_prefix=initial_prefix,
                                       add_options=add_options,
                                       remove_options=remove_options,
                                       fs=fs)

        state.regs.ip = address

        state.scratch.ins_addr = address
        state.scratch.bbl_addr = address
        state.scratch.stmt_idx = 0
        state.scratch.jumpkind = 'Ijk_Boring'

        return state


    def entry_point(self, args=None, env=None, sargc=None, **kwargs):
        '''
        entry_point     Returns a state reflecting the processor when execution
                        reaches the binary's entry point.

        @param args     Argv for the program as a python list. Optional.
        @param env      The program's environment as a python dict. Optional.
        @param sargc    If true, argc will be fully unconstrained even if you supply argv. Be very afraid.

        Any further params will be directly re-passed to StateGenerator.blank_state.
        '''

        state = self.blank_state(**kwargs)
        if state.has_plugin('cgc'):
            if isinstance(self._project.ld.main_bin, BackedCGC):
                for reg, val in self._project.ld.main_bin.initial_register_values():
                    if reg in state.arch.registers:
                        setattr(state.regs, reg, val)
                    elif reg == 'eflags':
                        pass
                    elif reg == 'fctrl':
                        state.regs.fpround = (val & 0xC00) >> 10
                    elif reg == 'fstat':
                        state.regs.fc3210 = (val & 0x4700)
                    elif reg == 'ftag':
                        empty_bools = [((val >> (x*2)) & 3) == 3 for x in xrange(8)]
                        tag_chars = [state.BVV(0 if x else 1, 8) for x in empty_bools]
                        for i, tag in enumerate(tag_chars):
                            setattr(state.regs, 'fpu_t%d' % i, tag)
                    elif reg in ('fiseg', 'fioff', 'foseg', 'fooff', 'fop'):
                        pass
                    elif reg == 'mxcsr':
                        state.regs.sseround = (val & 0x600) >> 9
                    else:
                        l.error("What is this register %s I have to translate?", reg)

                # Do all the writes
                writes_backer = self._project.ld.main_bin.writes_backer
                stdout = 1
                for size in writes_backer:
                    if size == 0:
                        continue
                    str_to_write = state.posix.files[1].content.load(state.posix.files[1].pos, size)
                    a = simuvex.SimActionData(state, 'file_1_0', 'write', addr=state.BVV(state.posix.files[1].pos, state.arch.bits), data=str_to_write, size=size)
                    state.posix.write(stdout, str_to_write, size)
                    state.log.add_action(a)

            else:
                # Set CGC-specific variables
                state.regs.eax = 0
                state.regs.ebx = 0
                state.regs.ecx = 0
                state.regs.edx = 0
                state.regs.edi = 0
                state.regs.esi = 0
                state.regs.esp = 0xbaaaaffc
                state.regs.ebp = 0
                #state.regs.eflags = s.BVV(0x202, 32)

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

            return state

        if args is not None:
            # Handle default values
            if env is None:
                env = {}

            # Prepare argc
            argc = state.BVV(len(args), state.arch.bits)
            if sargc is not None:
                argc = state.se.Unconstrained("argc", state.arch.bits)

            # Make string table for args/env/auxv
            table = StringTableSpec()

            # Add args to string table
            for arg in args:
                table.add_string(arg)
            table.add_null()

            # Add environment to string table
            for k, v in env.iteritems():
                table.add_string(k + '=' + v)
            table.add_null()

            # Prepare the auxiliary vector and add it to the end of the string table
            # TODO: Actually construct a real auxiliary vector
            aux = []
            for a, b in aux:
                table.add_pointer(a)
                table.add_pointer(b)
            table.add_null()
            table.add_null()

            # Dump the table onto the stack, calculate pointers to args, env, and auxv
            argv = table.dump(state, state.regs.sp)
            envp = argv + ((len(args) + 1) * state.arch.bytes)
            auxv = argv + ((len(args) + len(env) + 2) * state.arch.bytes)

            # Put argc on stack and fix the stack pointer
            newsp = argv - state.arch.bytes
            state.memory.store(newsp, argc, endness=state.arch.memory_endness)
            state.regs.sp = newsp

            if state.arch.name in ('PPC32',):
                state.stack_push(state.BVV(0, 32))
                state.stack_push(state.BVV(0, 32))
                state.stack_push(state.BVV(0, 32))
                state.stack_push(state.BVV(0, 32))
        else:
            state.stack_push(state.BVV(0, state.arch.bits))
            newsp = state.regs.sp
            state.memory.store(newsp, state.BVV(0, state.arch.bits), endness=state.arch.memory_endness)
            argv = newsp + state.arch.bytes
            argc = 0
            envp = argv
            auxv = argv

        # store argc argv envp in the posix plugin
        state.posix.argv = argv
        state.posix.argc = argc
        state.posix.environ = envp

        # drop in all the register values at the entry point
        for reg, val in self._arch.entry_register_values.iteritems():
            if isinstance(val, (int, long)):
                state.registers.store(reg, val, size=state.arch.bytes)
            elif isinstance(val, (str,)):
                if val == 'argc':
                    state.registers.store(reg, argc, size=state.arch.bytes)
                elif val == 'argv':
                    state.registers.store(reg, argv)
                elif val == 'envp':
                    state.registers.store(reg, envp)
                elif val == 'auxv':
                    state.registers.store(reg, auxv)
                elif val == 'ld_destructor':
                    # a pointer to the dynamic linker's destructor routine, to be called at exit
                    # or NULL. We like NULL. It makes things easier.
                    state.registers.store(reg, state.BVV(0, state.arch.bits))
                elif val == 'toc':
                    if self._ld.main_bin.ppc64_initial_rtoc is not None:
                        state.registers.store(reg, self._ld.main_bin.ppc64_initial_rtoc)
                        state.libc.ppc64_abiv = 'ppc64_1'
                else:
                    l.warning('Unknown entry point register value indicator "%s"', val)
            else:
                l.error('What the ass kind of default value is %s?', val)

        return state

    def full_init(self, *args, **kwargs):
        kwargs['address'] = self._project.extern_obj.get_pseudo_addr('angr##loader')
        state = self.entry_point(*args, **kwargs)
        return state
