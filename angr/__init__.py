""" Angr module """
from .project import *
from .functionmanager import *
from .variableseekr import *
from .regmap import *
from .mergeseekr import *
from .annocfg import *
from .path import *
from .errors import *
from .surveyor import *
from .service import *
from .analyses import *
from .analysis import *
from .tablespecs import *
from . import surveyors
from .blade import Blade
from .osconf import OSConf


l = logging.getLogger("angr.init")
l.setLevel(logging.INFO)

# Non-mandatory imports
try:
    from largescale.orgy import Orgy
except ImportError:
    l.info("Largescale module not available. Clone from git if needed.")