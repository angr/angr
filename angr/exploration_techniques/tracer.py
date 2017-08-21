import claripy
import logging

from . import ExplorationTechnique
from .oppologist import Oppologist

from .. import sim_options as so

from ..errors import AngrTracerError
from ..storage.file import SimDialogue, SimFile
from ..procedures import SIM_LIBRARIES
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
        self.r = runner
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

        # this is used to track constrained addresses
        self._address_concretization = []

    def setup(self, simgr):
        self.project = simgr._project

        # Check if we need to rebase QEMU's addr
        min_addr = self.project.loader.main_object.min_addr
        if self.r.base_addr != min_addr:
            l.warn("Our base address doesn't match %s's. Changing to ours at 0x%x", self.r.trace_source, min_addr)
            for i, a in enumerate(self.r.trace):
                self.r.trace[i] = a + min_addr - self.r.base_addr

        self._prepare_state(simgr)

    def _preconstrain_state(self, entry_state):
        """
        Preconstrain the entry state to the input.
        """

        if not self.preconstrain_input:
            return

        repair_entry_state_opts = False
        if so.TRACK_ACTION_HISTORY in entry_state.options:
            repair_entry_state_opts = True
            entry_state.options -= {so.TRACK_ACTION_HISTORY}

        if self.pov:  # a PoV, need to navigate the dialogue
            stdin_dialogue = entry_state.posix.get_file(0)
            for write in self.pov_file.writes:
                for b in write:
                    b_bvv = entry_state.se.BVV(b)
                    v = stdin_dialogue.read_from(1)
                    c = v == b_bvv
                    self.variable_map[list(v.variables)[0]] = c
                    self.preconstraints.append(c)
                    if so.REPLACEMENT_SOLVER in entry_state.options:
                        entry_state.se._solver.add_replacement(v, b_bvv, invalidate_cache=False)

            stdin_dialogue.seek(0)

        else:  # not a PoV, just raw input
            stdin = entry_state.posix.get_file(0)

            for b in self.input:
                v = stdin.read_from(1)
                b_bvv = entry_state.se.BVV(b)
                c = v == b_bvv
                # add the constraint for reconstraining later
                self.variable_map[list(v.variables)[0]] = c
                self.preconstraints.append(c)
                if so.REPLACEMENT_SOLVER in entry_state.options:
                    entry_state.se._solver.add_replacement(v, b_bvv, invalidate_cache=False)

            stdin.seek(0)

        if repair_entry_state_opts:
            entry_state.options |= {so.TRACK_ACTION_HISTORY}

        # add the preconstraints to the actual constraints on the state if we aren't replacing
        if so.REPLACEMENT_SOLVER not in entry_state.options:
            entry_state.add_constraints(*self.preconstraints)

    def _preconstrain_flag_page(self, entry_state, flag_bytes):
        """
        Preconstrain the data in the flag page.
        """
        if not self.preconstrain_flag:
            return

        for b in range(0x1000):
            v = flag_bytes[b]
            b_bvv = entry_state.se.BVV(self.r.magic[b])
            c = v == b_bvv
            self.variable_map[list(flag_bytes[b].variables)[0]] = c
            self.preconstraints.append(c)
            if so.REPLACEMENT_SOLVER in entry_state.options:
                entry_state.se._solver.add_replacement(v, b_bvv, invalidate_cache=False)

    def _prepare_state(simgr):
        """
        Prepare initial state.
        :param simgr: a fresh SimulationManager to be setup.
        """
        all_other_states = []
        active = simgr.active
        for states in simgr.stashes.itervalues():
            if states != active:
                all_other_states += states
        if len(all_other_states) or len(active) != 1 or active[0].history.recent_block_count > 1:
            l.warn("Using Tracer exploration technique on a non-fresh SimulationManager, re-initializing states.")

        if self.project.loader.main_object.os == "cgc":
            cache_tuple = self._cache_lookup()
            # if we're restoring from a cache, we preconstrain
            if cache_tuple is not None:
                bb_cnt, self.cgc_flag_bytes, state, claripy.ast.base.var_counter = cache_tuple
                self._cgc_prepare_paths(simgr, state)
                self._preconstrain_state(state)
                self.bb_cnt = bb_cnt
            else: # if we're not restoring from a cache, the cacher will preconstrain
                self._cgc_prepare_state(simgr)

        elif self.project.loader.main_object.os == "unix":
            l.warn("Tracer was heavily tested only for CGC. If it doesn't work for other platforms, we are sorry!")
            self._linux_prepare_state(simgr)

        raise AngrTracerError("Unsupported OS \"%s\" called _prepare_state", self.project.loader.main_object.os)

    def _prepare_dialogue(self):
        """
        Prepare a SimDialogue entry for stdin.
        """

        s = SimDialogue("/dev/stdin")
        for write in self.pov_file.writes:
            s.add_dialogue_entry(len(write))

        return {'/dev/stdin': s}

    def _cgc_prepare_state(self, simgr, state=None):
        """
        Prepare the initial state for CGC binaries.
        :param simgr: a fresh SimulationManager to be setup.
        :param state: optional state to use instead of preparing a fresh one.
        """

        # FixedRandom, FixedInReceive, and FixedOutTransmit always are applied as defaults
        SIM_LIBRARIES['cgcabi'].add('random', FixedRandom)
        SIM_LIBRARIES['cgcabi'].add('receive', FixedInReceive)
        SIM_LIBRARIES['cgcabi'].add('transmit', FixedOutTransmit)

        # if we're in crash mode we want the authentic system calls
        if not self.r.crash_mode:
            self._set_cgc_simprocedures()

        self._set_hooks()

        if not self.pov:
            fs = {'/dev/stdin': SimFile("/dev/stdin", "r", size=self.r.input_max_size)}
        else:
            fs = self._prepare_dialogue()

        entry_state = None
        if state is None:
            options = set()
            options.add(so.CGC_ZERO_FILL_UNCONSTRAINED_MEMORY)
            options.add(so.CGC_NO_SYMBOLIC_RECEIVE_LENGTH)
            options.add(so.REPLACEMENT_SOLVER)
            options.add(so.UNICORN_THRESHOLD_CONCRETIZATION)

            # try to enable unicorn, continue if it doesn't exist
            try:
                options.add(so.UNICORN)
                options.add(so.UNICORN_SYM_REGS_SUPPORT)
                options.add(so.UNICORN_HANDLE_TRANSMIT_SYSCALL)
                self.unicorn_enabled = True
                l.debug("Unicorn tracing enabled")
            except AttributeError:
                pass

            self.remove_options |= so.simplification | {so.LAZY_SOLVES, so.SUPPORT_FLOATING_POINT, so.EFFICIENT_STATE_MERGING}
            self.add_options |= options
            entry_state = self.project.factory.entry_state(fs=fs,
                                                           add_options=self.add_options,
                                                           remove_options=self.remove_options)

            csr = entry_state.unicorn.cooldown_symbolic_registers
            entry_state.unicorn.concretization_threshold_registers = 25000 / csr
            entry_state.unicorn.concretization_threshold_memory = 25000 / csr
        else:
            state.project = self.project
            # hookup the new files
            for name in fs:
                fs[name].set_state(state)
                for fd in state.posix.files:
                    if state.posix.files[fd].name == name:
                        state.posix.files[fd] = fs[name]
                        break

            state.history.recent_block_count = 0

            for option in self.add_options:
                state.options.add(option)

            for option in self.remove_options:
                state.options.discard(option)

            entry_state = state

        if not self.pov:
            entry_state.cgc.input_size = self.input_max_size

        if len(self._hooks):
            self._set_simproc_limits(entry_state)

        # preconstrain flag page
        self._preconstrain_flag_page(entry_state, self.cgc_flag_bytes)
        entry_state.memory.store(0x4347c000, claripy.Concat(*self.cgc_flag_bytes))

        if self._dump_syscall:
            entry_state.inspect.b('syscall', when=angr.BP_BEFORE, action=self.syscall)
        entry_state.inspect.b('state_step', when=angr.BP_AFTER, action=self.check_stack)

        simgr._make_stashes_dict(active=[entry_state])
        simgr.save_unsat = True
        simgr.save_unconstrained = self.crash_mode

        simgr.use_technique(Oppologist())
        l.info("Oppologist enabled")

    def syscall(self, state):
        syscall_addr = state.se.eval(state.ip)
        # 0xa000008 is terminate, which we exclude from syscall statistics.
        if syscall_addr != 0xa000008:
            args = angr.SYSCALL_CC['X86']['CGC'](self._p.arch).get_args(state, 4)
            d = {'addr': syscall_addr}
            for i in xrange(4):
                d['arg_%d' % i] = args[i]
                d['arg_%d_symbolic' % i] = args[i].ast.symbolic
            self._syscall.append(d)

    def check_stack(self, state):
        if state.memory.load(state.ip, state.ip.length).symbolic:
            l.debug("executing input-related code")
            self.crash_type = EXEC_STACK
            self.crash_state = state

    def _linux_prepare_state(self):
        """
        Prepare the initial state for Linux binaries.
        """
        for symbol in self.exclude_sim_procedures_list:
            self.project.unhook_symbol(symbol)

        if not self.crash_mode:
            self._set_linux_simprocedures()

        self._set_hooks()

        # fix stdin to the size of the input being traced
        fs = {'/dev/stdin': SimFile("/dev/stdin", "r", size=self.input_max_size)}

        options = set()
        options.add(so.CGC_ZERO_FILL_UNCONSTRAINED_MEMORY)
        options.add(so.BYPASS_UNSUPPORTED_SYSCALL)
        options.add(so.REPLACEMENT_SOLVER)
        options.add(so.UNICORN)
        options.add(so.UNICORN_HANDLE_TRANSMIT_SYSCALL)
        if self.crash_mode:
            options.add(so.TRACK_ACTION_HISTORY)

        self.remove_options |= so.simplification | {so.EFFICIENT_STATE_MERGING}
        self.add_options |= options
        entry_state = self.project.factory.full_init_state(fs=fs,
                                                           concrete_fs=True,
                                                           chroot=self.chroot,
                                                           add_options=self.add_options,
                                                           remove_options=self.remove_options,
                                                           args=self.r.argv)

        self._preconstrain_state(entry_state)

        # increase size of libc limits
        entry_state.libc.buf_symbolic_bytes = 1024
        entry_state.libc.max_str_len = 1024

        simgr._make_stashes_dict(active=[entry_state])
        simgr._immutable = True
        simgr.save_unsat = True
        simgr.save_unconstrained = self.crash_mode

        # Step forward until we catch up with QEMU
        if simgr.active[0].addr != self.r.trace[0]:
            simgr = simgr.explore(find=self.project.entry)
            simgr = simgr.drop(stash="unsat")
            simgr = simgr.unstash(from_stash="found",to_stash="active")

        # don't step here, because unlike CGC we aren't going to be starting
        # anywhere but the entry point

    def _set_cgc_simprocedures(self):
        for symbol in self.simprocedures:
            angr.SIM_LIBRARIES['cgcabi'].add(symbol, self.simprocedures[symbol])

    def _set_linux_simprocedures(self, project):
        for symbol in self.simprocedures:
            project.hook_symbol(symbol, self.simprocedures[symbol])

    @staticmethod
    def _set_simproc_limits(state):
        state.libc.max_str_len = 1000000
        state.libc.max_strtol_len = 10
        state.libc.max_memcpy_size = 0x100000
        state.libc.max_symbolic_bytes = 100
        state.libc.max_buffer_size = 0x100000

    def _set_hooks(self, project):
        for addr, proc in self._hooks.items():
            project.hook(addr, proc)

