from .successors import SimSuccessors
from .engine import SimEngine

from .vex import SimEngineVEX
from .procedure import SimEngineProcedure
from .unicorn import SimEngineUnicorn
from .failure import SimEngineFailure
from .syscall import SimEngineSyscall
from .concrete import SimEngineConcrete
from .hook import SimEngineHook
from .soot import SimEngineSoot

from .hub import EngineHub, EnginePreset


# This is a basic preset of essential engines.
# It is meant to serve as the boilerplate for other presets.
basic_preset = EnginePreset(['failure', 'syscall', 'hook'])
basic_preset.add_default_plugin('failure', SimEngineFailure)
basic_preset.add_default_plugin('syscall', SimEngineSyscall)
basic_preset.add_default_plugin('hook', SimEngineHook)
basic_preset.add_default_plugin('procedure', SimEngineProcedure)

basic_preset.procedure_engine = 'procedure'

# This is a VEX engine preset.
# It will be used as a default preset for engine hub.
vex_preset = basic_preset.copy()
EngineHub.register_preset('default', vex_preset)

vex_preset.add_default_plugin('unicorn', SimEngineUnicorn)
vex_preset.add_default_plugin('vex', SimEngineVEX)
vex_preset.add_default_plugin('concrete', SimEngineConcrete)

vex_preset.order = 'unicorn', 'vex', 'concrete'
vex_preset.default_engine = 'vex'

# Soot engine preset.
soot_preset = basic_preset.copy()
EngineHub.register_preset('Soot', soot_preset)
soot_preset.add_default_plugin('soot', SimEngineSoot)
soot_preset.add_default_plugin('vex', SimEngineVEX)
soot_preset.default_engine = 'soot'
soot_preset.order = ['soot', 'vex']
