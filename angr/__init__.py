""" angr module """
# pylint: disable=wildcard-import

import logging
logging.getLogger("angr.")

# this must happen first, prior to initializing analyses
from .sim_procedure import SimProcedure
from .procedures import SIM_PROCEDURES, SimProcedures

from .misc import Loggers
import sys
i = 0
while True:
    i += 1
    try:
        module = sys._getframe(i).f_globals.get('__name__')
    except ValueError:
        break

    if module == '__main__' or module == '__console__':
        loggers = Loggers()
        break
    elif module is not None and module.startswith('nose.'):
        break

del sys, i, module

from . import sim_options
options = sim_options  # alias

# enums
from .state_plugins.inspect import BP_BEFORE, BP_AFTER, BP_BOTH, BP_IPDB, BP_IPYTHON

# other stuff

from .state_plugins.inspect import BP

from .project import *
from .errors import *
#from .surveyor import *
from .service import *
from .analyses import *
from .analysis import *
from .tablespecs import *
#from . import surveyors
from .blade import Blade
from .simos import SimOS
from .sim_context import SimContext
from .callable import Callable
from . import knowledge
from . import exploration_techniques
from . import type_backend
from . import sim_type as types

from .sim_state import SimState
from .engines import SimEngineVEX
from .calling_conventions import DEFAULT_CC, SYSCALL_CC
