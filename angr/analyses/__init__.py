registered_analyses = {}

def register_analysis(cls, name):
    registered_analyses[name] = cls

from .analysis import Analysis

from .cfg import CFGFast, CFGAccurate, CFG, CFGArchOptions
from .cdg import CDG
from .ddg import DDG
from .vfg import VFG
from .boyscout import BoyScout
from .girlscout import GirlScout
from .backward_slice import BackwardSlice
from .veritesting import Veritesting
from .vsa_ddg import VSA_DDG
from .bindiff import BinDiff
from .dfg import DFG
from .loopfinder import LoopFinder
from .congruency_check import CongruencyCheck
from .static_hooker import StaticHooker
from .reassembler import Reassembler
from .binary_optimizer import BinaryOptimizer
from .disassembly import Disassembly
from .variable_recovery import VariableRecovery, VariableRecoveryFast
from .identifier import Identifier
from .callee_cleanup_finder import CalleeCleanupFinder


# Plugin presets
from ..misc import PluginPreset


class DefaultPluginsPreset(PluginPreset):

    @classmethod
    def apply_preset(cls, analyses, *args, **kwargs):
        # CFG analyses
        analyses.register_default('CFG', CFG)
        analyses.register_default('CFGFast', CFGFast)
        analyses.register_default('CFGAccurate', CFGAccurate)

        # Identifier
        analyses.register_default('Identifier', Identifier)

        # Variable recovery
        analyses.register_default('VariableRecover', VariableRecovery)
        analyses.register_default('VariableRecoveryFast', VariableRecoveryFast)

        # Other analyses
        analyses.register_default('BackwardSlice', BackwardSlice)
        analyses.register_default('BinaryOptimizer', BinaryOptimizer)
        analyses.register_default('BinDiff', BinDiff)
        analyses.register_default('BoyScout', BoyScout)
        analyses.register_default('CaleeCleanupFinder', CalleeCleanupFinder)
        analyses.register_default('CDG', CDG)
        analyses.register_default('CongruencyCheck', CongruencyCheck)
        analyses.register_default('DDG', DDG)
        analyses.register_default('DFG', DFG)
        analyses.register_default('Disassembly', Disassembly)
        analyses.register_default('GirlScout', GirlScout)
        analyses.register_default('LoopFinder', LoopFinder)
        analyses.register_default('Reassembler', Reassembler)
        analyses.register_default('StaticHooker', StaticHooker)
        analyses.register_default('Veritesting', Veritesting)
        analyses.register_default('VFG', VFG)
        analyses.register_default('VSA_DDG', VSA_DDG)


ALL_PRESETS = {
    'default': DefaultPluginsPreset,
}
