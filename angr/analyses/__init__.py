from .analysis import Analysis, AnalysesHub
from ..misc.ux import deprecated

def register_analysis(cls, name):
    AnalysesHub.register_default(name, cls)

from .cfg import CFGFast, CFGEmulated, CFG, CFGArchOptions
from .cdg import CDG
from .ddg import DDG
from .vfg import VFG
from .boyscout import BoyScout
#from .girlscout import GirlScout
from .backward_slice import BackwardSlice
from .veritesting import Veritesting
from .vsa_ddg import VSA_DDG
from .bindiff import BinDiff
from .loopfinder import LoopFinder
from .congruency_check import CongruencyCheck
from .static_hooker import StaticHooker
from .reassembler import Reassembler
from .binary_optimizer import BinaryOptimizer
from .disassembly import Disassembly
from .variable_recovery import VariableRecovery, VariableRecoveryFast
from .identifier import Identifier
from .callee_cleanup_finder import CalleeCleanupFinder
from .reaching_definitions import ReachingDefinitionAnalysis
from .calling_convention import CallingConventionAnalysis
from .code_tagging import CodeTagging
