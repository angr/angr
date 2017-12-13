#pylint:disable=wildcard-import
from .plugin import *
from .libc import *
from .posix import *
from .inspect import *
from .solver import *
from .symbolic_memory import SimSymbolicMemory
from .abstract_memory import *
from .fast_memory import *
from .log import *
from .history import *
from .scratch import *
from .cgc import *
from .gdb import *
from .uc_manager import *
from .unicorn_engine import Unicorn
from .sim_action import *
from .sim_action_object import *
from .sim_event import *
from .callstack import *
from .globals import *
from .preconstrainer import *
from .loop_data import *
from .view import *

# Plugin presets
from ..misc.plugins import PluginPreset


class DefaultPluginPreset(PluginPreset):

    @classmethod
    def apply_preset(cls, hub, *args, **kwargs):
        hub.register_default('callstack', CallStack)
        hub.register_default('cgc', SimStateCGC)
        hub.register_default('gdb', GDB)
        hub.register_default('globals', SimStateGlobals)
        hub.register_default('history', SimStateHistory)
        hub.register_default('inspector', SimInspector)
        hub.register_default('libc', SimStateLibc)
        hub.register_default('log', SimStateLog)
        hub.register_default('posix', SimStateSystem)
        hub.register_default('preconstrainer', SimStatePreconstrainer)
        hub.register_default('scratch', SimStateScratch)
        hub.register_default('solver_engine', SimSolver)
        hub.register_default('memory', SimSymbolicMemory)
        hub.register_default('registers', SimSymbolicMemory)
        hub.register_default('uc_manager', SimUCManager)
        hub.register_default('unicorn', Unicorn)
        hub.register_default('regs', SimRegNameView)
        hub.register_default('mem', SimMemView)


ALL_PRESETS = {
    'default': DefaultPluginPreset
}
