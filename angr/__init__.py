""" angr module """
# pylint: disable=wildcard-import

import logging
logging.getLogger("angr.")

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

from .procedures import SIM_PROCEDURES, SimProcedures

from .project import *
from .path import *
from .errors import *
from .surveyor import *
from .service import *
from .analyses import *
from .analysis import *
from .tablespecs import *
from . import surveyors
from .blade import Blade
from .simos import SimOS
from .path_group import PathGroup
from .surveyors.caller import Callable
from . import knowledge
from . import exploration_techniques

from .sim_state import SimState
from .engines import SimEngineVEX
from .calling_conventions import DefaultCC
from .procedures.sim_procedure import SimProcedure
from . import sim_options as options
