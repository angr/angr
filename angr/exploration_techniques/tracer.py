import claripy
import logging

from . import ExplorationTechnique

from .. import sim_options as o

from ..errors import AngrTracerError
from ..procedures.cgc import fixed_in_receive as receive

from ..procedures.cgc.fixed_random import FixedRandom
from ..procedures.cgc.fixed_in_receive import FixedInReceive
from ..procedures.cgc.fixed_out_transmit import FixedOutTransmit

from ..misc.tracerpov import TracerPoV
from ..misc.cachemanager import LocalCacheManager

l = logging.getLogger("angr.exploration_techniques.tracer")

# global writable attribute used for specifying cache procedures
GlobalCacheManager = None

EXEC_STACK = 'EXEC_STACK'
QEMU_CRASH = 'SEG_FAULT'

class Tracer(ExplorationTechnique):
    """
    An exploration technique that follows an angr path with a concrete input.
    """

    def __init__(self, runner, preconstrain_input=True, preconstrain_flag=True,
                 resiliency=True, chroot=None, add_options=None, remove_options=None,
                 trim_history=True, dump_syscall=False, dump_cache=True, max_size=None,
                 argv=None, keep_predecessors=1):
        """
        :param
