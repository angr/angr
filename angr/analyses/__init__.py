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
from .variable_recovery import VariableRecovery
from .identifier import Identifier
from .callee_cleanup_finder import CalleeCleanupFinder
