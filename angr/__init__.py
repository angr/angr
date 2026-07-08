# pylint: disable=wrong-import-position
from __future__ import annotations

__version__ = "9.2.224.dev0"

if bytes is str:
    raise Exception("""

=-=-=-=-=-=-=-=-=-=-=-=-=  WELCOME TO THE FUTURE!  =-=-=-=-=-=-=-=-=-=-=-=-=-=

angr has transitioned to python 3. Due to the small size of the team behind it,
we can't reasonably maintain compatibility between both python 2 and python 3.
If you want to continue using the most recent version of angr (you definitely
want that, trust us) you should upgrade to python 3. It's like getting your
vaccinations. It hurts a little bit initially but in the end it's worth it.

For more information, see here: https://docs.angr.io/appendix/migration

Good luck!
""")

# isort: off
from .utils.formatting import setup_terminal

setup_terminal()
del setup_terminal

# let's set up some bootstrap logging
import logging

logging.getLogger("angr").addHandler(logging.NullHandler())
from .misc.loggers import Loggers

loggers = Loggers()
del Loggers
del logging

# angr.state_plugins and angr.sim_state are mutually dependent: the plugin modules register themselves
# on SimState at import time, while SimState needs the SimStatePlugin base class. Importing the
# state_plugins package to completion here, before anything pulls in sim_state, is the one ordering
# that resolves the cycle.
from . import state_plugins  # noqa: F401

# SimProcedure must be bound on the ``angr`` package before the procedures package loads, because the
# hundreds of built-in SimProcedures are defined as ``class Foo(angr.SimProcedure)`` and dereference
# that attribute at class-definition time.
from .sim_procedure import SimProcedure

# isort: on

from . import (
    analyses,
    concretization_strategies,
    engines,
    exploration_techniques,
    knowledge_plugins,
    sim_options,
)
from . import sim_manager as manager
from . import sim_type as types
from .analyses import Analysis, register_analysis
from .blade import Blade
from .block import Block
from .calling_conventions import DEFAULT_CC, SYSCALL_CC, PointerWrapper, SimCC, default_cc
from .distributed import Server
from .emulator import Emulator, EmulatorStopReason
from .errors import (
    AngrAIError,
    AngrAnalysisError,
    AngrAnnotatedCFGError,
    AngrAssemblyError,
    AngrBackwardSlicingError,
    AngrBladeError,
    AngrBladeSimProcError,
    AngrCallableError,
    AngrCallableMultistateError,
    AngrCFGError,
    AngrCorruptDBError,
    AngrDataGraphError,
    AngrDBError,
    AngrDDGError,
    AngrDecompilationError,
    AngrDelayJobNotice,
    AngrDirectorError,
    AngrError,
    AngrExitError,
    AngrExplorationTechniqueError,
    AngrExplorerError,
    AngrForwardAnalysisError,
    AngrIncompatibleDBError,
    AngrIncongruencyError,
    AngrInvalidArgumentError,
    AngrJobMergingFailureNotice,
    AngrJobWideningFailureNotice,
    AngrLifterError,
    AngrLoopAnalysisError,
    AngrMissingTypeError,
    AngrNoPluginError,
    AngrPathError,
    AngrRuntimeError,
    AngrSimOSError,
    AngrSkipJobNotice,
    AngrSurveyorError,
    AngrSyscallError,
    AngrTracerError,
    AngrTypeError,
    AngrUnsupportedSyscallError,
    AngrValueError,
    AngrVaultError,
    AngrVFGError,
    AngrVFGRestartAnalysisNotice,
    PathUnreachableError,
    SimAbstractMemoryError,
    SimActionError,
    SimCCallError,
    SimCCError,
    SimConcreteBreakpointError,
    SimConcreteMemoryError,
    SimConcreteRegisterError,
    SimEmptyCallStackError,
    SimEngineError,
    SimError,
    SimEventError,
    SimException,
    SimExpressionError,
    SimFastMemoryError,
    SimFastPathError,
    SimFileError,
    SimFilesystemError,
    SimHeapError,
    SimIRSBError,
    SimIRSBNoDecodeError,
    SimMemoryAddressError,
    SimMemoryError,
    SimMemoryLimitError,
    SimMemoryMissingError,
    SimMergeError,
    SimMissingTempError,
    SimOperationError,
    SimPosixError,
    SimProcedureArgumentError,
    SimProcedureError,
    SimRegionMapError,
    SimReliftException,
    SimSegfaultError,
    SimSegfaultException,
    SimShadowStackError,
    SimSlicerError,
    SimSolverError,
    SimSolverModeError,
    SimSolverOptionError,
    SimStateError,
    SimStatementError,
    SimStateOptionsError,
    SimSymbolicFilesystemError,
    SimTranslationError,
    SimUCManagerAllocationError,
    SimUCManagerError,
    SimulationManagerError,
    SimUnicornError,
    SimUnicornSymbolic,
    SimUnicornUnsupport,
    SimUninitializedAccessError,
    SimUnsatError,
    SimUnsupportedError,
    SimValueError,
    SimZeroDivisionException,
    TracerEnvironmentError,
    UnsupportedCCallError,
    UnsupportedDirtyError,
    UnsupportedIRExprError,
    UnsupportedIROpError,
    UnsupportedIRStmtError,
    UnsupportedNodeTypeError,
    UnsupportedSyscallError,
)
from .exploration_techniques import ExplorationTechnique
from .knowledge_base import KnowledgeBase
from .llm_client import LLMClient
from .procedures import SIM_LIBRARIES, SIM_PROCEDURES, SIM_TYPE_COLLECTIONS, SimProcedures
from .procedures.definitions import load_external_definitions
from .project import Project, load_shellcode
from .rust import analyses as rust_analyses
from .rust import knowledge_plugins as rust_knowledge_plugins
from .sim_manager import SimulationManager
from .sim_state import SimState
from .simos import SimOS
from .state_hierarchy import StateHierarchy
from .state_plugins import SimStatePlugin
from .state_plugins.filesystem import SimHostFilesystem, SimMount
from .state_plugins.heap import PTChunk, SimHeapBrk, SimHeapPTMalloc
from .state_plugins.inspect import BP, BP_AFTER, BP_BEFORE, BP_BOTH, BP_IPDB, BP_IPYTHON
from .storage.file import (
    SimFile,
    SimFileBase,
    SimFileDescriptor,
    SimFileDescriptorDuplex,
    SimFileStream,
    SimPackets,
    SimPacketsStream,
)

options = sim_options  # alias

# now that we have everything loaded, re-grab the list of loggers
loggers.load_all_loggers()

load_external_definitions()

__all__ = (
    "BP",
    "BP_AFTER",
    "BP_BEFORE",
    "BP_BOTH",
    "BP_IPDB",
    "BP_IPYTHON",
    "DEFAULT_CC",
    "SIM_LIBRARIES",
    "SIM_PROCEDURES",
    "SIM_TYPE_COLLECTIONS",
    "SYSCALL_CC",
    "Analysis",
    "AngrAIError",
    "AngrAnalysisError",
    "AngrAnnotatedCFGError",
    "AngrAssemblyError",
    "AngrBackwardSlicingError",
    "AngrBladeError",
    "AngrBladeSimProcError",
    "AngrCFGError",
    "AngrCallableError",
    "AngrCallableMultistateError",
    "AngrCorruptDBError",
    "AngrDBError",
    "AngrDDGError",
    "AngrDataGraphError",
    "AngrDecompilationError",
    "AngrDelayJobNotice",
    "AngrDirectorError",
    "AngrError",
    "AngrExitError",
    "AngrExplorationTechniqueError",
    "AngrExplorerError",
    "AngrForwardAnalysisError",
    "AngrIncompatibleDBError",
    "AngrIncongruencyError",
    "AngrInvalidArgumentError",
    "AngrJobMergingFailureNotice",
    "AngrJobWideningFailureNotice",
    "AngrLifterError",
    "AngrLoopAnalysisError",
    "AngrMissingTypeError",
    "AngrNoPluginError",
    "AngrPathError",
    "AngrRuntimeError",
    "AngrSimOSError",
    "AngrSkipJobNotice",
    "AngrSurveyorError",
    "AngrSyscallError",
    "AngrTracerError",
    "AngrTypeError",
    "AngrUnsupportedSyscallError",
    "AngrVFGError",
    "AngrVFGRestartAnalysisNotice",
    "AngrValueError",
    "AngrVaultError",
    "Blade",
    "Block",
    "Emulator",
    "EmulatorStopReason",
    "ExplorationTechnique",
    "KnowledgeBase",
    "LLMClient",
    "PTChunk",
    "PathUnreachableError",
    "PointerWrapper",
    "Project",
    "Server",
    "SimAbstractMemoryError",
    "SimActionError",
    "SimCC",
    "SimCCError",
    "SimCCallError",
    "SimConcreteBreakpointError",
    "SimConcreteMemoryError",
    "SimConcreteRegisterError",
    "SimEmptyCallStackError",
    "SimEngineError",
    "SimError",
    "SimEventError",
    "SimException",
    "SimExpressionError",
    "SimFastMemoryError",
    "SimFastPathError",
    "SimFile",
    "SimFileBase",
    "SimFileDescriptor",
    "SimFileDescriptorDuplex",
    "SimFileError",
    "SimFileStream",
    "SimFilesystemError",
    "SimHeapBrk",
    "SimHeapError",
    "SimHeapPTMalloc",
    "SimHostFilesystem",
    "SimIRSBError",
    "SimIRSBNoDecodeError",
    "SimMemoryAddressError",
    "SimMemoryError",
    "SimMemoryLimitError",
    "SimMemoryMissingError",
    "SimMergeError",
    "SimMissingTempError",
    "SimMount",
    "SimOS",
    "SimOperationError",
    "SimPackets",
    "SimPacketsStream",
    "SimPosixError",
    "SimProcedure",
    "SimProcedureArgumentError",
    "SimProcedureError",
    "SimProcedures",
    "SimRegionMapError",
    "SimReliftException",
    "SimSegfaultError",
    "SimSegfaultException",
    "SimShadowStackError",
    "SimSlicerError",
    "SimSolverError",
    "SimSolverModeError",
    "SimSolverOptionError",
    "SimState",
    "SimStateError",
    "SimStateOptionsError",
    "SimStatePlugin",
    "SimStatementError",
    "SimSymbolicFilesystemError",
    "SimTranslationError",
    "SimUCManagerAllocationError",
    "SimUCManagerError",
    "SimUnicornError",
    "SimUnicornSymbolic",
    "SimUnicornUnsupport",
    "SimUninitializedAccessError",
    "SimUnsatError",
    "SimUnsupportedError",
    "SimValueError",
    "SimZeroDivisionException",
    "SimulationManager",
    "SimulationManagerError",
    "StateHierarchy",
    "TracerEnvironmentError",
    "UnsupportedCCallError",
    "UnsupportedDirtyError",
    "UnsupportedIRExprError",
    "UnsupportedIROpError",
    "UnsupportedIRStmtError",
    "UnsupportedNodeTypeError",
    "UnsupportedSyscallError",
    "analyses",
    "concretization_strategies",
    "default_cc",
    "engines",
    "exploration_techniques",
    "knowledge_plugins",
    "load_shellcode",
    "manager",
    "options",
    "register_analysis",
    "rust_analyses",
    "rust_knowledge_plugins",
    "sim_options",
    "types",
)
