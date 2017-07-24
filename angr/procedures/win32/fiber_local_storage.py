import angr

KEY = 'win32_fls'

def mutate_dict(state):
    d = dict(state.globals.get(KEY, {}))
    state.globals[KEY] = d
    return d

def has_index(state, idx):
    if KEY not in state.globals:
        return False
    return idx in state.globals[KEY]

class FlsAlloc(angr.SimProcedure):
    def run(self, callback):
        if not self.state.solver.is_true(callback == 0):
            raise angr.errors.SimValueError("Can't handle callback function in FlsAlloc")

        d = mutate_dict(self.state)
        new_key = len(d) + 1
        d[new_key] = self.state.se.BVV(0, self.state.arch.bits)
        return new_key

class FlsFree(angr.SimProcedure):
    def run(self, index):
        set_val = self.inline_call(FlsSetValue, (index, self.state.se.BVV(0, self.state.arch.bits)))
        return set_val.ret_expr

class FlsSetValue(angr.SimProcedure):
    def run(self, index, value):
        conc_indexs = self.state.se.any_n_int(index, 2)
        if len(conc_indexs) != 1:
            raise angr.errors.SimValueError("Can't handle symbolic index in FlsSetValue")
        conc_index = conc_indexs[0]

        if not has_index(self.state, conc_index):
            return 0

        mutate_dict(self.state)[conc_index] = value
        return 1

class FlsGetValue(angr.SimProcedure):
    def run(self, index):
        conc_indexs = self.state.se.any_n_int(index, 2)
        if len(conc_indexs) != 1:
            raise angr.errors.SimValueError("Can't handle symbolic index in FlsGetValue")
        conc_index = conc_indexs[0]

        if not has_index(self.state, conc_index):
            return 0

        return self.globals[KEY][conc_index]
