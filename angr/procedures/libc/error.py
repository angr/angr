import angr

######################################
# error
######################################

class error(angr.SimProcedure):
    #pylint:disable=arguments-differ,missing-class-docstring

    NO_RET = None
    DYNAMIC_RET = True

    def run(self, status, errnum, fmt):  # pylint:disable=unused-argument
        fd = self.state.posix.get_fd(1)
        fprintf = angr.SIM_PROCEDURES['libc']['fprintf']
        self.inline_call(fprintf, fd, fmt)  # FIXME: This will not properly replace format strings

        if status.concrete and self.state.solver.eval(status) != 0:
            self.exit(status)

    def dynamic_returns(self, blocks, **kwargs) -> bool:
        # Execute those blocks with a blank state, and then dump the arguments
        blank_state = angr.SimState(project=self.project, mode="fastpath", cle_memory_backer=self.project.loader.memory,
                                    add_options={angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                                                 angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS})
        # Execute each block
        state = blank_state
        for b in blocks:
            irsb = self.project.factory.default_engine.process(state, irsb=b, force_addr=b.addr)
            if irsb.successors:
                state = irsb.successors[0]
            else:
                break

        # take a look at the first argument (status)
        cc = angr.DEFAULT_CC[self.arch.name](self.arch)
        ty = angr.sim_type.parse_signature('void x(int, int, char*)').with_arch(self.arch)
        args = cc.get_args(state, ty)
        if args[0].concrete and state.solver.eval(args[0]) == 0:
            return True
        return False
