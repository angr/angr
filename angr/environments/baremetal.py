import logging

from ..sim_environment import SimEnvironment

l = logging.getLogger("angr.environments.baremetal")

class SimBareMetal(SimEnvironment):
    """
    This is the main interface for bare metal analysis, for programs with
    none or comparable weak user/kernel-land seperation and direct hardware
    accesses.
    In comparison to "normal" Userland SimEnvironments, BareMetalEnvironments
    do require an explicit memory map and an explicit interrupt-table.

    TODO: Define structure of memory_map. Preliminary, it's a dict, however,
          object-ifying it might be useful.
    """

    def __init__(self, project, memory_map, peripheral_map=None, 
                 interrupt_table=None, **kwargs):
        super(SimBareMetal, self).__init__(project, **kwargs)

    def configure_project(self):
        super(SimBareMetal, self).configure_project()

    def state_blank(self, **kwargs):
        state = super(SimBareMetal, self).state_blank(**kwargs)

        state.get_plugin('irq') 

    def interrupt(self, state, number):
        return False
