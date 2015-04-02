from .plugin import SimStatePlugin

class SimRegNameView(SimStatePlugin):
    def __init__(self):
        super(SimRegNameView, self).__init__()

    def __getattr__(self, k):
        try:
            return self.state.reg_expr(self.state.arch.registers[k][0])
        except KeyError:
            return getattr(super(SimRegNameView, self), k)

    def __setattr__(self, k, v):
        if k == 'state':
            return object.__setattr__(self, k, v)

        try:
            return self.state.store_reg(self.state.arch.registers[k][0], v)
        except KeyError:
            raise AttributeError(k)

    def __dir__(self):
        return self.state.arch.registers.keys()

    def copy(self):
        return SimRegNameView()

    def merge(self, others, merge_flag, flag_values):
        return False, [ ]

    def widen(self, others, merge_flag, flag_values):
        return False, [ ]
