from ..baremetal import SimBareMetal

class SimARMv7M(SimBareMetal):
    """
    Focuses on BareMetal-Systems running the ARMv7M architecture as for
    instanced used on Cortex-M3 based MCUs
    """
    def __init__(self, project, **kwargs):
        super(SimARMv7M, self).__init__(project, **kwargs)

    def state_blank(self, **kwargs):
        state = super(SimARMv7M, self).state_blank(**kwargs)
        state.regs.sp = self.interrut_table[0]
        return state

    def state_entry(self, **kwargs):
        state = self.state_blank(**kwargs)
        state.regs.pc = self.interrut_table[1]
        return state


