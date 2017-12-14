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
from .view import *

# Plugin presets
from ..misc.plugins import PluginPreset


class DefaultPluginPreset(PluginPreset):

    def apply_preset(self, state):
        state.register_default('callstack', CallStack)
        state.register_default('cgc', SimStateCGC)
        state.register_default('gdb', GDB)
        state.register_default('globals', SimStateGlobals)
        state.register_default('history', SimStateHistory)
        state.register_default('inspector', SimInspector)
        state.register_default('libc', SimStateLibc)
        state.register_default('log', SimStateLog)
        state.register_default('posix', SimStateSystem)
        state.register_default('preconstrainer', SimStatePreconstrainer)
        state.register_default('scratch', SimStateScratch)
        state.register_default('solver_engine', SimSolver)
        state.register_default('memory', SimSymbolicMemory)
        state.register_default('registers', SimSymbolicMemory)
        state.register_default('uc_manager', SimUCManager)
        state.register_default('unicorn', Unicorn)
        state.register_default('regs', SimRegNameView)
        state.register_default('mem', SimMemView)
