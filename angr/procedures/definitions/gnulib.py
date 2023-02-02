import logging

from ...sim_type import SimTypeFunction, \
    SimTypeInt, \
    SimTypePointer, \
    SimTypeChar, \
    SimTypeBottom

from .. import SIM_PROCEDURES as P
from . import SimLibrary


_l = logging.getLogger(name=__name__)


gnulib = SimLibrary()
gnulib.add_all_from_dict(P['gnulib'])
gnulib.set_non_returning('xstrtol_fatal')


#
# parsed function prototypes
#

_gnulib_decls = \
    {
        # void  xstrtol_fatal(enum strtol_error err, int opt_idx, char c, struct option const *long_options, char const *arg)
        "xstrtol_fatal": SimTypeFunction([SimTypeInt(signed=True), SimTypeInt(signed=True), SimTypeChar(), SimTypePointer(SimTypeInt(), offset=0), SimTypePointer(SimTypeChar(), offset=0)], SimTypeBottom(label="void"), arg_names=["err", "opt_idx", "c", "long_options", "arg"]),
    }
