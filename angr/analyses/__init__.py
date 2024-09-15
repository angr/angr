# pylint:disable=wrong-import-position
from __future__ import annotations
from .analysis import Analysis, AnalysesHub


def register_analysis(cls, name):
    AnalysesHub.register_default(name, cls)


from .forward_analysis import ForwardAnalysis, visitors
from .propagator import PropagatorAnalysis
from .cfg import CFGFast, CFGEmulated, CFG, CFGArchOptions, CFGFastSoot
from .cdg import CDG
from .ddg import DDG
from .vfg import VFG
from .boyscout import BoyScout

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
from .reaching_definitions import ReachingDefinitionsAnalysis
from .calling_convention import CallingConventionAnalysis
from .code_tagging import CodeTagging
from .stack_pointer_tracker import StackPointerTracker
from .dominance_frontier import DominanceFrontier
from .data_dep import DataDependencyGraphAnalysis
from .decompiler import Decompiler
from .soot_class_hierarchy import SootClassHierarchy
from .xrefs import XRefsAnalysis
from .init_finder import InitializationFinder
from .complete_calling_conventions import CompleteCallingConventionsAnalysis
from .typehoon import Typehoon
from .proximity_graph import ProximityGraphAnalysis
from .vtable import VtableFinder
from .find_objects_static import StaticObjectFinder
from .class_identifier import ClassIdentifier
from .flirt import FlirtAnalysis
from .s_propagator import SPropagatorAnalysis
from .s_reaching_definitions import SReachingDefinitionsAnalysis
from .s_liveness import SLivenessAnalysis
