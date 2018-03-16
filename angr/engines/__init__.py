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

vex_preset.add_default_plugin('unicorn', SimEngineUnicorn)
vex_preset.add_default_plugin('failure', SimEngineFailure)
vex_preset.add_default_plugin('syscall', SimEngineSyscall)
vex_preset.add_default_plugin('hook', SimEngineHook)
vex_preset.add_default_plugin('vex', SimEngineVEX)
vex_preset.add_default_plugin('procedure', SimEngineProcedure)

vex_preset.order = 'failure', 'syscall', 'hook', 'unicorn', 'vex'
vex_preset.default_engine = 'vex'
vex_preset.procedure_engine = 'procedure'
