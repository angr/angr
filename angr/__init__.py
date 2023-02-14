# pylint: disable=wildcard-import
# pylint: disable=wrong-import-position

__version__ = "9.2.38"

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

# import hook: pkg_resources is too slow to import, but it is used by some other packages that angr depends on. while
# we upstream our fixes, we replace it with a light-weight solution.
from .misc.import_hooks import import_fake_pkg_resources

import_fake_pkg_resources(force=False)

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
from .calling_conventions import DEFAULT_CC, SYSCALL_CC, PointerWrapper, SimCC
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

# for compatibility reasons
from . import sim_manager as manager

# now that we have everything loaded, re-grab the list of loggers
loggers.load_all_loggers()
