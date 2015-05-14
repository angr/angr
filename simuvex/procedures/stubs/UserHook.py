import simuvex

class UserHook(simuvex.SimProcedure):
    NO_RET = True

    # pylint: disable=arguments-differ
    def run(self, user_func=None, user_kwargs=None, default_return_addr=None):
        result = user_func(self.state, **user_kwargs)
        if result is None:
            self.add_successor(self.state, default_return_addr, self.state.se.true, 'Ijk_NoHook')
        else:
            for state in result:
                self.add_successor(state, state.ip, state.scratch.guard, state.scratch.jumpkind)
