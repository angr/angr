# pylint: disable=wildcard-import

# first: let's set up some bootstrap logging
import logging
logging.getLogger("angr").addHandler(logging.NullHandler())
from .misc.loggers import Loggers
loggers = Loggers()
del Loggers
del logging

# this must happen first, prior to initializing analyses
from .sim_procedure import SimProcedure
from .procedures import SIM_PROCEDURES, SimProcedures, SIM_LIBRARIES

from . import sim_options
options = sim_options  # alias

# enums
from .state_plugins.inspect import BP_BEFORE, BP_AFTER, BP_BOTH, BP_IPDB, BP_IPYTHON

# other stuff
from .state_plugins.inspect import BP
from .state_plugins import SimStatePlugin

from .project import *
from .errors import *
#from . import surveyors
#from .surveyor import *
#from .service import *
from .blade import Blade
from .simos import SimOS
from .sim_manager import SimulationManager
from .analyses import Analysis, register_analysis
from . import analyses
from . import knowledge_plugins
from . import exploration_techniques
from .exploration_techniques import ExplorationTechnique
from . import type_backend
from . import sim_type as types
from .state_hierarchy import StateHierarchy

from .sim_state import SimState
from .engines import SimEngineVEX, SimEngine
from .calling_conventions import DEFAULT_CC, SYSCALL_CC, PointerWrapper, SimCC
from .storage.file import SimFileBase, SimFile, SimPackets, SimFileStream, SimPacketsStream, SimFileDescriptor, SimFileDescriptorDuplex
from .state_plugins.filesystem import SimMount, SimHostFilesystem

# for compatibility reasons
from . import sim_manager as manager

# now that we have everything loaded, re-grab the list of loggers
loggers.load_all_loggers()

# make sure there's not a git/pip mix
import os
def _module_location(i):
	_module_location = __import__(i).__file__
	if '__init__' in _module_location:
		return os.path.dirname(os.path.dirname(os.path.dirname(_module_location)))
	else:
		return os.path.dirname(os.path.dirname(_module_location))

_angr_location = _module_location('angr')
for _m in { 'ailment', 'ana', 'archinfo', 'claripy', 'cle', 'cooldict', 'idalink', 'mulpyplexer', 'pysoot', 'pyvex' }:
	try:
		_mloc = _module_location(_m)
	except ImportError:
		continue
	if _mloc != _angr_location:
		logging.getLogger("angr").warning(
			"pypi/git installation mismatch: angr is installed in %s and dependency %s is installed in %s. This will almost certainly lead to problems.",
			_angr_location, _m, _mloc
		)
