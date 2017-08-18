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

    def __init__(self, runner, hooks=None, simprocedures=None, preconstrain_input=True,
                 preconstrain_flag=True, resiliency=True, chroot=None, add_options=None,
                 remove_options=None, trim_history=True, dump_syscall=False, dump_cache=True,
                 max_size=None, exclude_sim_procedures_list=None, keep_predecessors=1):
        """
        :param runner: a Runner class that contains the basic block trace.
        :param hooks: a dictionary of hooks to add.
        :param simprocedures: dictionary of replacement simprocedures.
        :param preconstrain_input: should the path be preconstrained to the
                                   provided input.
        :param preconstrain_flag: should the path have the cgc flag page
                                  preconstrained.
        :param resiliency: should we continue to step forward even if qemu and
                           angr disagree?
        :param chroot: trace the program as though it were executing in a chroot.
        :param add_options: add options to the state which used to do tracing.
        :param remove_options: remove options from the state which is used to
                               do tracing.
        :param trim_history: trim the history of a path.
        :param dump_syscall: true if we want to dump the syscall information.
        :param max_size: optionally set max size of input. Defaults to size
                         of preconstrained input.
        :param exclude_sim_procedures_list: what SimProcedures to not hook at load time.
                                            Defaults to ["malloc","free","calloc","realloc"].
        :param keep_predecessors: number of states before the final state we
                                  should preserve. Default 1, must be greater than 0.
        """
        self.preconstrain_input = preconstrain_input
        self.preconstrain_flag = preconstrain_flag
        self.simprocedures = {} if simprocedures is None else simprocedures
        self._hooks = {} if hooks is None else hooks
        self.input_max_size = max_size or len(input) if input is not None else None
        self.exclude_sim_procedures_list = exclude_sim_procedures_list or ["malloc", "free", "calloc", "realloc"]

        for h in self._hooks:
            l.debug("Hooking %#x -> %s", h, self._hooks[h].display_name)

        self.resiliency = resiliency
        self.chroot = chroot
        self.add_options = set() if add_options is None else add_options
        self.trim_history = trim_history
        self.constrained_addrs = []

        # the final state after execution with input/pov_file
        self.final_state = None

        cm = LocalCacheManager(dump_cache=dump_cache) if GlobalCacheManager is None else GlobalCacheManager
        # cache managers need the tracer to be set for them
        self._cache_manager = cm
        self._cache_manager.set_tracer(self)

        # set by a cache manager
        self._loaded_from_cache = False

        if remove_options is None:
            self.remove_options = set()
        else:
            self.remove_options = remove_options

        # set up cache hook
        receive.cache_hook = self._cache_manager.cacher

        # CGC flag data
        self.cgc_flag_bytes = [claripy.BVS("cgc-flag-byte-%d" % i, 8) for i in xrange(0x1000)]

        # Check if we need to rebase to QEMU's addr
        if self.qemu_base_addr != self._p.loader.main_object.min_addr:
            l.warn("Our base address doesn't match QEMU's. Changing ours to 0x%x",self.qemu_base_addr)

        self.preconstraints = []

        # map of variable string names to preconstraints, for re-applying
        # constraints
        self.variable_map = {}

        # initialize the basic block counter to 0
        self.bb_cnt = 0

        # keep track of the last basic block we hit
        if keep_predecessors < 1:
            raise ValueError("Must have keep_predecessors >= 1")
        self.predecessors = [None] * keep_predecessors

        # whether we should follow the qemu trace
        self.no_follow = False

        # this will be set by _prepare_paths
        self.unicorn_enabled = False

        # initilize the syscall statistics if the flag is on
        self._dump_syscall = dump_syscall
        if self._dump_syscall:
            self._syscall = []

        self.simgr = self._prepare_paths()

        # this is used to track constrained addresses
        self._address_concretization = []
