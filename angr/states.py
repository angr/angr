import logging
import simuvex

l = logging.getLogger('angr.states')

class StateGenerator(object):
    def __init__(self, project):
        self._project = project
        self._arch = project.arch
        self._ld = project.ld

    def blank_state(self, mode='symbolic', address=None, initial_prefix=None,
                options=None, add_options=None, remove_options=None):

        if address is None:
            address = self._ld.main_bin.entry_point

        memory_backer = self._ld.memory
        if add_options is not None and simuvex.o.ABSTRACT_MEMORY in add_options:
            # Adjust the memory backer when using abstract memory
            if memory_backer is not None:
                memory_backer = {'global': memory_backer}

        state = self._arch.make_state(memory_backer=memory_backer,
                                    mode=mode, options=options,
                                    initial_prefix=initial_prefix,
                                    add_options=add_options, remove_options=remove_options)

        state.store_reg(self._arch.ip_offset, address)
        return state


    def entry_point(self, mode='symbolic', args=None, env=None, sargc=None, **kwargs):
        '''
        entry_point - Returns a state reflecting the processor when execution
                      reaches the binary's entry point.

        @param mode - The execution mode.
        @param args - Argv for the program as a python list. Optional.
        @param env - The program's environment as a python dict. Optional.
        @param sargc - If true, argc will be fully unconstrained even if you supply argv. Be very afraid.

        Any further params will be directly re-passed to StateGenerator.blank_state.
        '''

        state = self.blank_state(mode, **kwargs)

        args = self._project.argv if args is None else args
        sargc = self._project.symbolic_argc if sargc is None else args

        if args is not None:
            # Handle default values
            if env is None:
                env = {}

            # Make string table for args/env
            sp = state.sp_expr()
            envs = ["%s=%s"%(x[0], x[1]) for x in env.iteritems()]
            argc = state.BVV(len(args), state.arch.bits)
            #envl = state.BVV(len(envs), state.arch.bits)
            if sargc is not None:
                argc = state.se.Unconstrained("argc", state.arch.bits)
            argv = state.make_string_table(args + [None] + envs, sp.model.value)

            envp = argv + ((len(args) + 1) * state.arch.bytes)

            # put argc on stack and fixup the stack pointer
            newsp = argv - state.arch.bytes
            state.store_mem(newsp, argc, endness=state.arch.memory_endness)
            state.store_reg(state.arch.sp_offset, newsp)
        else:
            state.stack_push(state.BVV(0, state.arch.bits))
            newsp = state.sp_expr()
            state.store_mem(newsp, state.BVV(0, state.arch.bits), endness=state.arch.memory_endness)
            argv = newsp + state.arch.bytes
            argc = 0
            envp = argv

        # store argc argv envp in the posix plugin
        state['posix'].argv = argv
        state['posix'].argc = argc
        state['posix'].environ = envp

        # drop in all the register values at the entry point
        for reg, val in self._arch.entry_register_values.iteritems():
            if type(val) in (int, long):
                state.store_reg(reg, val)
            elif type(val) in (str,):
                if val == '&argc':
                    state.store_reg(reg, newsp)
                elif val == 'argc':
                    state.store_reg(reg, argc)
                elif val == 'argv':
                    state.store_reg(reg, argv)
                elif val == 'envp':
                    state.store_reg(reg, envp)
                else:
                    l.warning('Unknown entry point register value indicator "%s"' % val)
            else:
                l.error('What the ass kind of default value is %s?' % val)

        # les hax
        state.abiv = None
        if self._ld.main_bin.ppc64_initial_rtoc is not None:
            state.store_reg('rtoc', self._ld.main_bin.ppc64_initial_rtoc)
            state.abiv = 'ppc64_1'

        return state
