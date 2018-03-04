from collections import defaultdict, OrderedDict

from .successors import SimSuccessors
from .engine import SimEngine

from .vex import SimEngineVEX
from .procedure import SimEngineProcedure
from .unicorn import SimEngineUnicorn
from .failure import SimEngineFailure
from .syscall import SimEngineSyscall
from .hook import SimEngineHook

from .hub import EngineHub, EnginePreset

vex_preset = EnginePreset()
EngineHub.register_preset('default', vex_preset)
vex_preset.set_order(['unicorn', 'default_engine'])
vex_preset.add_default_plugin('unicorn', SimEngineUnicorn)
vex_preset.add_default_plugin('failure', SimEngineFailure)
vex_preset.add_default_plugin('syscall', SimEngineSyscall)
vex_preset.add_default_plugin('hook', SimEngineHook)
vex_preset.add_default_plugin('default_engine', SimEngineVEX)
vex_preset.add_default_plugin('procedure_engine', SimEngineProcedure)
