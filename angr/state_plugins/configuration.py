
from .plugin import SimStatePlugin


class SimStateConfiguration(SimStatePlugin):

    __slots__ = [ 'symbolic_ip_max_targets' ]

    def __init__(self,
                 symbolic_ip_max_targets=None
                 ):
        super(SimStateConfiguration, self).__init__()

        self.symbolic_ip_max_targets = 16384 if symbolic_ip_max_targets is None else symbolic_ip_max_targets

    def copy(self):
        s = SimStateConfiguration()
        s.symbolic_ip_max_targets = self.symbolic_ip_max_targets
        return s


from ..sim_state import SimState
SimState.register_default('config', SimStateConfiguration)
