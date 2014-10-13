import simuvex

######################################
# pthread_create
# obviously adapted from __libc_start_main
######################################
class pthread_create(simuvex.SimProcedure):
    ADDS_EXITS = True

    def __init__(self): #pylint:disable=W0231

        # Get main pc from arguments
        code_addr = self.arg(2)
        func_arg = self.arg(0)

        # Create the new state as well
        new_state=self.state.copy()
        new_state.stack_push(func_arg)
        # This is a stupid hack, but it should cause the simulated execution to halt on returning, which is correct
        new_state.stack_push(self.state.BVV(0, self.state.arch.bits))

        self.add_exits(simuvex.s_exit.SimExit(expr=code_addr, state=new_state, jumpkind='Ijk_Call'))
        self.add_refs(simuvex.SimCodeRef(self.addr, self.stmt_from, code_addr, [], []))
        self.ret(self.state.BVV(0, self.state.arch.bits))
