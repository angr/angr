# pylint: disable=wildcard-import
# pylint: disable=wrong-import-position
from __future__ import annotations

__version__ = "9.2.159"

if bytes is str:
    raise Exception(
        """

=-=-=-=-=-=-=-=-=-=-=-=-=  WELCOME TO THE FUTURE!  =-=-=-=-=-=-=-=-=-=-=-=-=-=

angr has transitioned to python 3. Due to the small size of the team behind it,
we can't reasonably maintain compatibility between both python 2 and python 3.
If you want to continue using the most recent version of angr (you definitely
want that, trust us) you should upgrade to python 3. It's like getting your
vaccinations. It hurts a little bit initially but in the end it's worth it.

For more information, see here: https://docs.angr.io/appendix/migration

Good luck!
"""
    )

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

# this must happen first, prior to initializing analyses
from .sim_procedure import SimProcedure
from .procedures import SIM_PROCEDURES, SimProcedures, SIM_LIBRARIES, SIM_TYPE_COLLECTIONS

from . import sim_options

options = sim_options  # alias

# enums
from .state_plugins.inspect import BP_BEFORE, BP_AFTER, BP_BOTH, BP_IPDB, BP_IPYTHON

# other stuff
from .state_plugins.inspect import BP
from .state_plugins import SimStatePlugin

from .project import Project, load_shellcode
from .errors import (
    AngrError,
    AngrRuntimeError,
    AngrValueError,
    AngrLifterError,
    AngrExitError,
    AngrPathError,
    AngrVaultError,
    PathUnreachableError,
    SimulationManagerError,
    AngrInvalidArgumentError,
    AngrSurveyorError,
    AngrAnalysisError,
    AngrBladeError,
    AngrBladeSimProcError,
    AngrAnnotatedCFGError,
    AngrBackwardSlicingError,
    AngrCallableError,
    AngrCallableMultistateError,
    AngrSyscallError,
    AngrSimOSError,
    AngrAssemblyError,
    AngrTypeError,
    AngrMissingTypeError,
    AngrIncongruencyError,
    AngrForwardAnalysisError,
    AngrSkipJobNotice,
    AngrDelayJobNotice,
    AngrJobMergingFailureNotice,
    AngrJobWideningFailureNotice,
    AngrCFGError,
    AngrVFGError,
    AngrVFGRestartAnalysisNotice,
    AngrDataGraphError,
    AngrDDGError,
    AngrLoopAnalysisError,
    AngrExplorationTechniqueError,
    AngrExplorerError,
    AngrDirectorError,
    AngrTracerError,
    AngrDBError,
    AngrCorruptDBError,
    AngrIncompatibleDBError,
    TracerEnvironmentError,
    SimError,
    SimStateError,
    SimMergeError,
    SimMemoryError,
    SimMemoryMissingError,
    SimAbstractMemoryError,
    SimRegionMapError,
    SimMemoryLimitError,
    SimMemoryAddressError,
    SimFastMemoryError,
    SimEventError,
    SimPosixError,
    SimFilesystemError,
    SimSymbolicFilesystemError,
    SimFileError,
    SimHeapError,
    SimUnsupportedError,
    SimSolverError,
    SimSolverModeError,
    SimSolverOptionError,
    SimValueError,
    SimUnsatError,
    SimOperationError,
    UnsupportedIROpError,
    SimExpressionError,
    UnsupportedIRExprError,
    SimCCallError,
    UnsupportedCCallError,
    SimUninitializedAccessError,
    SimStatementError,
    UnsupportedIRStmtError,
    UnsupportedDirtyError,
    SimMissingTempError,
    SimEngineError,
    SimIRSBError,
    SimTranslationError,
    SimProcedureError,
    SimProcedureArgumentError,
    SimShadowStackError,
    SimFastPathError,
    SimIRSBNoDecodeError,
    AngrUnsupportedSyscallError,
    UnsupportedSyscallError,
    SimReliftException,
    SimSlicerError,
    SimActionError,
    SimCCError,
    SimUCManagerError,
    SimUCManagerAllocationError,
    SimUnicornUnsupport,
    SimUnicornError,
    SimUnicornSymbolic,
    SimEmptyCallStackError,
    SimStateOptionsError,
    SimException,
    SimSegfaultException,
    SimSegfaultError,
    SimZeroDivisionException,
    AngrNoPluginError,
    SimConcreteMemoryError,
    SimConcreteRegisterError,
    SimConcreteBreakpointError,
    AngrDecompilationError,
    UnsupportedNodeTypeError,
)
from .blade import Blade
from .simos import SimOS
from .block import Block
from .sim_manager import SimulationManager
from .analyses import Analysis, register_analysis
from . import analyses
from . import knowledge_plugins
from . import exploration_techniques
from .exploration_techniques import ExplorationTechnique
from . import sim_type as types
from .state_hierarchy import StateHierarchy

from .sim_state import SimState
from . import engines
from .calling_conventions import default_cc, DEFAULT_CC, SYSCALL_CC, PointerWrapper, SimCC
from .storage.file import (
    SimFileBase,
    SimFile,
    SimPackets,
    SimFileStream,
    SimPacketsStream,
    SimFileDescriptor,
    SimFileDescriptorDuplex,
)
from .state_plugins.filesystem import SimMount, SimHostFilesystem
from .state_plugins.heap import SimHeapBrk, SimHeapPTMalloc, PTChunk
from . import concretization_strategies
from .distributed import Server
from .knowledge_base import KnowledgeBase
from .procedures.definitions import load_external_definitions

# for compatibility reasons
from . import sim_manager as manager

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
    "ExplorationTechnique",
    "KnowledgeBase",
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
    "sim_options",
    "types",
)
