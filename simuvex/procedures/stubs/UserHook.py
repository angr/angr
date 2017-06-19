import simuvex

class UserHook(simuvex.SimProcedure):
    NO_RET = True

    # pylint: disable=arguments-differ
    def run(self, user_func=None, length=None):
        result = user_func(self.state)
        if result is None:
            self.successors.add_successor(self.state, self.addr+length, self.state.se.true, 'Ijk_NoHook')
        else:
            for state in result:
                self.successors.add_successor(state, state.ip, state.scratch.guard, state.scratch.jumpkind)
