import os
import time
import angr
import socket
import claripy
import simuvex
import tempfile
import signal
import subprocess
import shellphish_qemu
from .tracerpov import TracerPoV
from .cachemanager import LocalCacheManager
from .simprocedures import receive
from .simprocedures import FixedOutTransmit, FixedInReceive, FixedRandom
from simuvex import s_options as so
from simuvex import s_cc

import logging

l = logging.getLogger("tracer.Tracer")
# global writable attribute used for specifying cache procedures
GlobalCacheManager = None

EXEC_STACK = 'EXEC_STACK'
QEMU_CRASH = 'SEG_FAULT'

class TracerInstallError(Exception):
    pass


class TracerEnvironmentError(Exception):
    pass


class TracerMisfollowError(Exception):
    pass


class TracerDynamicTraceOOBError(Exception):
    pass

class TracerTimeout(Exception):
    pass

class Tracer(object):
    '''
    Trace an angr path with a concrete input
    '''

    def __init__(self, binary, input=None, pov_file=None, simprocedures=None,
                 hooks=None, seed=None, preconstrain_input=True,
                 preconstrain_flag=True, resiliency=True, chroot=None,
                 add_options=None, remove_options=None, trim_history=True,
                 project=None, dump_syscall=False, dump_cache=True,
                 max_size = None, exclude_sim_procedures_list=None,
                 argv = None):
        """
        :param binary: path to the binary to be traced
        :param input: concrete input string to feed to binary
        :param povfile: CGC PoV describing the input to trace
        :param hooks: A dictionary of hooks to add
        :param simprocedures: dictionary of replacement simprocedures
        :param seed: optional seed used for randomness, will be passed to QEMU
        :param preconstrain_input: should the path be preconstrained to the
            provided input
        :param preconstrain_flag: should the path have the cgc flag page
            preconstrained
        :param resiliency: should we continue to step forward even if qemu and
            angr disagree?
        :param chroot: trace the program as though it were executing in a
            chroot
        :param add_options: add options to the state which used to do tracing
        :param remove_options: remove options from the state which is used to
            do tracing
        :param trim_history: Trim the history of a path.
        :param project: The original project.
        :param dump_syscall: True if we want to dump the syscall information
        :param max_size: Optionally set max size of input. Defaults to size
            of preconstrained input.
        :param exclude_sim_procedures_list: What SimProcedures to hook or not
            at load time. Defaults to ["malloc","free","calloc","realloc"]
        :param argv: Optionally specify argv params (i,e,: ['./calc', 'parm1'])
            defaults to binary name with no params.
        """

        self.binary = binary
        self.input = input
        self.pov_file = pov_file
        self.preconstrain_input = preconstrain_input
        self.preconstrain_flag = preconstrain_flag
        self.simprocedures = {} if simprocedures is None else simprocedures
        self._hooks = {} if hooks is None else hooks
        self.input_max_size = max_size or len(input)
        self.exclude_sim_procedures_list = exclude_sim_procedures_list or ["malloc","free","calloc","realloc"]
        self.argv = argv or [binary]

        for h in self._hooks:
            l.debug("Hooking %#x -> %s", h, self._hooks[h].__name__)

        if isinstance(seed, (int, long)):
            seed = str(seed)
        self.seed = seed
        self.resiliency = resiliency
        self.chroot = chroot
        self.add_options = set() if add_options is None else add_options
        self.trim_history = trim_history
        self.constrained_addrs = []
        # the final state after execution with input/pov_file
        self.final_state = None
        # the path after execution with input/pov_file
        self.path = None

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

        if self.pov_file is None and self.input is None:
            raise ValueError("must specify input or pov_file")

        if self.pov_file is not None and self.input is not None:
            raise ValueError("cannot specify both a pov_file and an input")

        # validate seed
        if self.seed is not None:
            try:
                iseed = int(self.seed)
                if iseed > 4294967295 or iseed < 0:
                    raise ValueError
            except ValueError:
                raise ValueError(
                    "the passed seed is either not an integer or is not between 0 and UINT_MAX"
                    )

        # set up cache hook
        receive.cache_hook = self._cache_manager.cacher

        # a PoV was provided
        if self.pov_file is not None:
            self.pov_file = TracerPoV(self.pov_file)
            self.pov = True
        else:
            self.pov = False

        # internal project object, useful for obtaining certain kinds of info
        if project is None:
            self._p = angr.Project(self.binary)
        else:
            self._p = project
        self.base = None
        self.tracer_qemu = None
        self.tracer_qemu_path = None
        self._setup()

        l.debug("accumulating basic block trace...")
        l.debug("self.tracer_qemu_path: %s", self.tracer_qemu_path)

        # does the input cause a crash?
        self.crash_mode = False
        # if the input causes a crash, what address does it crash at?
        self.crash_addr = None

        self.crash_state = None

        self.crash_type = None

        # CGC flag data
        self.cgc_flag_bytes = [claripy.BVS("cgc-flag-byte-%d" % i, 8) for i in xrange(0x1000)]

        # content of the magic flag page as reported by QEMU
        # we need this to keep symbolic traces following the same path
        # as their dynamic counterpart
        self._magic_content = None

        # will set crash_mode correctly and also discover the QEMU base addr
        self.trace = self.dynamic_trace()

        l.info("trace consists of %d basic blocks", len(self.trace))

        # Check if we need to rebase to QEMU's addr
        if self.qemu_base_addr != self._p.loader.main_bin.get_min_addr():
            l.warn("Our base address doesn't match QEMU's. Changing ours to 0x%x",self.qemu_base_addr)

        self.preconstraints = []

        # map of variable string names to preconstraints, for re-applying
        # constraints
        self.variable_map = {}

        # initialize the basic block counter to 0
        self.bb_cnt = 0

        # keep track of the last basic block we hit
        self.previous = None
        self.previous_addr = None

        # whether we should follow the qemu trace
        self.no_follow = False

        # this will be set by _prepare_paths
        self.unicorn_enabled = False

        # initilize the syscall statistics if the flag is on
        self._dump_syscall = dump_syscall
        if self._dump_syscall:
            self._syscall = []

        self.path_group = self._prepare_paths()

        # this is used to track constrained addresses
        self._address_concretization = []

# EXPOSED

    def next_branch(self):
        """
        windup the tracer to the next branch

        :return: a path_group describing the possible paths at the next branch
                 branches which weren't taken by the dynamic trace are placed
                 into the 'missed' stash. Paths in the 'missed' stash still
                 have preconstraints which should be removed using the
                 remove_preconstraints method.
        """
        while len(self.path_group.active) == 1:
            current = self.path_group.active[0]

            try:
                if current.state.scratch.executed_block_count > 1:
                    # executed unicorn fix bb_cnt
                    self.bb_cnt += current.state.scratch.executed_block_count - 1 - current.state.scratch.executed_syscall_count
            except AttributeError:
                pass

            if not self.no_follow:

                # expected behavor, the dynamic trace and symbolic trace hit
                # the same basic block
                if self.bb_cnt >= len(self.trace):
                    return self.path_group

                if current.addr == self.trace[self.bb_cnt]:
                    self.bb_cnt += 1

                # angr steps through the same basic block twice when a syscall
                # occurs
                elif current.addr == self.previous_addr or \
                        self._p._simos.syscall_table.get_by_addr(self.previous_addr) is not None:
                    pass
                elif current.jumpkind.startswith("Ijk_Sys"):
                    self.bb_cnt += 1

                # handle library calls and simprocedures
                elif self._p.is_hooked(current.addr) or \
                        self._p._simos.syscall_table.get_by_addr(current.addr) is not None \
                        or not self._address_in_binary(current.addr):

                    # If dynamic trace is in the PLT stub, update bb_cnt until it's out
                    while self._addr_in_plt(self.trace[self.bb_cnt]):
                        self.bb_cnt += 1

                # handle hooked functions
                # we use current._project since it seems to be different than self._p
                elif current._project.is_hooked(self.previous_addr) and self.previous_addr in self._hooks:
                    l.debug("ending hook for %s", current._project.hooked_by(self.previous_addr))
                    l.debug("previous addr %#x", self.previous_addr)
                    l.debug("bb_cnt %d", self.bb_cnt)
                    # we need step to the return
                    current_addr = current.addr
                    while current_addr != self.trace[self.bb_cnt] and self.bb_cnt < len(self.trace):
                        self.bb_cnt += 1
                    # step 1 more for the normal step that would happen
                    self.bb_cnt += 1
                    l.debug("bb_cnt after the correction %d", self.bb_cnt)
                    if self.bb_cnt >= len(self.trace):
                        return self.path_group

                else:
                    l.error(
                        "the dynamic trace and the symbolic trace disagreed"
                           )

                    l.error("[%s] dynamic [0x%x], symbolic [0x%x]",
                            self.binary,
                            self.trace[self.bb_cnt],
                            current.addr)

                    l.error("inputs was %r", self.input)
                    if self.resiliency:
                        l.error("TracerMisfollowError encountered")
                        l.warning("entering no follow mode")
                        self.no_follow = True
                    else:
                        raise TracerMisfollowError

            # shouldn't need to copy
            self.previous = current
            # TODO this shouldn't be needed, fish fix the bug plesae
            self.previous_addr = current.addr

            # Basic block's max size in angr is greater than the one in Qemu
            # We follow the one in Qemu
            if self.bb_cnt >= len(self.trace):
                bbl_max_bytes = 800
            else:
                y2 = self.trace[self.bb_cnt]
                y1 = self.trace[self.bb_cnt - 1]
                bbl_max_bytes = y2 - y1
                if bbl_max_bytes <= 0:
                    bbl_max_bytes = 800

            # detect back loops
            # this might still break for huge basic blocks with back loops
            # but it seems unlikely
            try:
                bl = self._p.factory.block(self.trace[self.bb_cnt-1],
                        backup_state=current.state)
                back_targets = set(bl.vex.constant_jump_targets) & set(bl.instruction_addrs)
                if self.bb_cnt < len(self.trace) and self.trace[self.bb_cnt] in back_targets:
                    target_to_jumpkind = bl.vex.constant_jump_targets_and_jumpkinds
                    if target_to_jumpkind[self.trace[self.bb_cnt]] == "Ijk_Boring":
                        bbl_max_bytes = 800
            except (simuvex.s_errors.SimMemoryError, simuvex.s_errors.SimEngineError):
                bbl_max_bytes = 800

            # if we're not in crash mode we don't care about the history
            if self.trim_history and not self.crash_mode:
                current.trim_history()

            self.prev_path_group = self.path_group
            self.path_group = self.path_group.step(size=bbl_max_bytes)
        
            if self.crash_type == EXEC_STACK:
                self.path_group = self.path_group.stash(from_stash='active',
                        to_stash='crashed')
                return self.path_group
            # if our input was preconstrained we have to keep on the lookout
            # for unsat paths
            if self.preconstrain_input:
                self.path_group = self.path_group.stash(from_stash='unsat',
                                                        to_stash='active')

            self.path_group = self.path_group.drop(stash='unsat')

            # check to see if we reached a deadend
            if self.bb_cnt >= len(self.trace):
                tpg = self.path_group.step()
                # if we're in crash mode let's populate the crashed stash
                if self.crash_mode:
                    self.crash_type = QEMU_CRASH
                    tpg = tpg.stash(from_stash='active', to_stash='crashed')
                    return tpg
                # if we're in normal follow mode, just step the path to
                # the deadend
                else:
                    if len(tpg.active) == 0:
                        self.path_group = tpg
                        return self.path_group

        # if we stepped to a point where there are no active paths,
        # return the path_group
        if len(self.path_group.active) == 0:
            # possibly we want to have different behaviour if we're in
            # crash mode
            return self.path_group

        # if we have to ditch the trace we use satisfiability
        # or if a split occurs in a library routine
        a_paths = self.path_group.active

        if self.no_follow or all(map(
                lambda p: not self._address_in_binary(p.addr), a_paths
                )):
            self.path_group = self.path_group.prune(to_stash='missed')
        else:
            l.debug("bb %d / %d", self.bb_cnt, len(self.trace))
            self.path_group = self.path_group.stash_not_addr(
                                           self.trace[self.bb_cnt],
                                           to_stash='missed')
        if len(self.path_group.active) > 1: # rarely we get two active paths
            self.path_group = self.path_group.prune(to_stash='missed')

        if len(self.path_group.active) > 1: # might still be two active
            self.path_group = self.path_group.stash(
                    to_stash='missed',
                    filter_func=lambda x: x.jumpkind == "Ijk_EmWarn"
            )

        # make sure we only have one or zero active paths at this point
        assert len(self.path_group.active) < 2

        rpg = self.path_group

        # something weird... maybe we hit a rep instruction?
        # qemu and vex have slightly different behaviors...
        if not self.path_group.active[0].state.se.satisfiable():
            l.warning("detected small discrepency between qemu and angr, "
                    "attempting to fix known cases")
            # did our missed branch try to go back to a rep?
            target = self.path_group.missed[0].addr
            if self._p.arch.name == 'X86' or self._p.arch.name == 'AMD64':

                # does it looks like a rep? rep ret doesn't count!
                if self._p.factory.block(target).bytes.startswith("\xf3") and \
                   not self._p.factory.block(target).bytes.startswith("\xf3\xc3"):

                    l.info("rep discrepency detected, repairing...")
                    # swap the stashes
                    s = self.path_group.move('missed', 'chosen')
                    s = s.move('active', 'missed')
                    s = s.move('chosen', 'active')
                    self.path_group = s

        self.path_group = self.path_group.drop(stash='missed')

        return rpg

    def _grab_concretization_results(self, state):
        """
        grabs the concretized result so we can add the constraint ourselves
        """
        variables = state.inspect.address_concretization_expr.variables
        hit_indices = self.to_indices(variables)

        # only grab ones that match the constrained addrs
        add_constraints = False
        for action in self.constrained_addrs:
            var_indices = self.to_indices(action.addr.variables)
            if var_indices == hit_indices:
                add_constraints = True
                break

        if add_constraints:
            addr = state.inspect.address_concretization_expr
            result = state.inspect.address_concretization_result
            if result is None:
                l.warning("addr concretization result is None")
                return
            self._address_concretization.append((addr, result))

    @staticmethod
    def to_indices(variables):
        variables = [v for v in variables if v.startswith("file_/dev/stdin")]
        indices = map(lambda y: int(y.split("_")[3], 16), variables)
        return sorted(indices)

    def _dont_add_constraints(self, state):
        '''
        obnoxious way to handle this, should ONLY be called from 'run'
        '''

        # for each constrained addrs check to see if the variables match,
        # if so keep the constraints

        variables = state.inspect.address_concretization_expr.variables
        hit_indices = self.to_indices(variables)

        add_constraints = False
        for action in self.constrained_addrs:
            var_indices = self.to_indices(action.addr.variables)
            if var_indices == hit_indices:
                add_constraints = True
                break
        state.inspect.address_concretization_add_constraints = add_constraints

    def run(self, constrained_addrs=None):
        '''
        run a trace to completion

        :param constrained_addrs: addresses which have had constraints applied
            to them and should not be removed
        :return: a deadended path of a complete symbolic run of the program
                 with self.input
        '''

        # keep calling next_branch until it quits
        branches = None
        while (branches is None or len(branches.active)) and self.bb_cnt < len(self.trace):
            branches = self.next_branch()

            # if we spot a crashed path in crash mode return the goods
            if self.crash_mode and 'crashed' in branches.stashes:
                if self.crash_type == EXEC_STACK:
                    return self.path_group.crashed[0], self.crash_state
                elif self.crash_type == QEMU_CRASH:
                    last_block = self.trace[self.bb_cnt - 1]
                    l.info("crash occured in basic block %x", last_block)

                # time to recover the crashing state

                # before we step through and collect the actions we have to set
                # up a special case for address concretization in the case of a
                # controlled read or write vulnerability

                if constrained_addrs is None:
                    self.constrained_addrs = []
                else:
                    self.constrained_addrs = constrained_addrs

                bp1 = self.previous.state.inspect.b(
                    'address_concretization',
                    simuvex.BP_BEFORE,
                    action=self._dont_add_constraints)

                bp2 = self.previous.state.inspect.b(
                    'address_concretization',
                    simuvex.BP_AFTER,
                    action=self._grab_concretization_results)

                # step to the end of the crashing basic block,
                # to capture its actions
                self.previous.step()

                # Add the constraints from concretized addrs back
                self.previous._run = None
                for var, concrete_vals in self._address_concretization:
                    if len(concrete_vals) > 0:
                        l.debug("constraining addr to be %#x", concrete_vals[0])
                        self.previous.state.add_constraints(var == concrete_vals[0])

                # then we step again up to the crashing instruction
                p_block = self._p.factory.block(self.previous.addr,
                        backup_state=self.previous.state)
                inst_cnt = len(p_block.instruction_addrs)
                insts = 0 if inst_cnt == 0 else inst_cnt - 1
                succs = self.previous.step(num_inst=insts)
                if len(succs) > 0:
                    if len(succs) > 1:
                        succs = [s for s in succs if s.state.se.satisfiable()]
                    self.previous = succs[0]

                # remove the preconstraints
                l.debug("removing preconstraints")
                self.remove_preconstraints(self.previous)
                self.previous._run = None

                l.debug("reconstraining... ")
                self.reconstrain(self.previous)

                l.debug("final step...")
                self.previous.step()

                # now remove our breakpoints since other people might not want them
                self.previous.state.inspect.remove_breakpoint("address_concretization", bp1)
                self.previous.state.inspect.remove_breakpoint("address_concretization", bp2)

                successors = self.previous.next_run.successors
                successors += self.previous.next_run.unconstrained_successors
                state = successors[0]

                l.debug("tracing done!")
                self.final_state = state
                self.path = self.previous
                return (self.previous, state)

        # this is a concrete trace, there should only be ONE path
        all_paths = branches.active + branches.deadended
        if len(all_paths) != 1:
            raise TracerMisfollowError("program did not behave correctly, \
                    expected only one path")

        # the caller is responsible for removing preconstraints
        self.final_state = None
        self.path = all_paths[0]
        return all_paths[0], None

    def remove_preconstraints(self, path, to_composite_solver=True, simplify=True):

        if not (self.preconstrain_input or self.preconstrain_flag):
            return

        # cache key set creation
        precon_cache_keys = set()

        for con in self.preconstraints:
            precon_cache_keys.add(con.cache_key)

        # if we used the replacement solver we didn't add constraints we need to remove so keep all constraints
        if so.REPLACEMENT_SOLVER in path.state.options:
            new_constraints = path.state.se.constraints
        else:
            new_constraints = filter(lambda x: x.cache_key not in precon_cache_keys, path.state.se.constraints)


        if path.state.has_plugin("zen_plugin"):
            new_constraints = path.state.get_plugin("zen_plugin").filter_constraints(new_constraints)

        if to_composite_solver:
            path.state.options.discard(so.REPLACEMENT_SOLVER)
            path.state.options.add(so.COMPOSITE_SOLVER)
        path.state.release_plugin('solver_engine')
        path.state.add_constraints(*new_constraints)
        l.debug("downsizing unpreconstrained state")
        path.state.downsize()
        if simplify:
            l.debug("simplifying solver")
            path.state.se.simplify()
            l.debug("simplification done")

        path.state.se._solver.result = None

    def reconstrain(self, path):
        '''
        re-apply preconstraints to improve solver time, hopefully these
        constraints still allow us to do meaningful things to state
        '''

        # test all solver splits
        subsolvers = path.state.se._solver.split()

        for solver in subsolvers:
            solver.timeout = 1000 * 10  # 10 seconds
            if not solver.satisfiable():
                for var in solver.variables:
                    if var in self.variable_map:
                        path.state.add_constraints(self.variable_map[var])
                    else:
                        l.warning("var %s not found in self.variable_map", var)

# SETUP

    def _setup(self):
        '''
        make sure the environment is sane and we have everything we need to do
        a trace
        '''
        # check the binary
        if not os.access(self.binary, os.X_OK):
            if os.path.isfile(self.binary):
                l.error("\"%s\" binary is not executable", self.binary)
                raise TracerEnvironmentError
            else:
                l.error("\"%s\" binary does not exist", self.binary)
                raise TracerEnvironmentError

        self.os = self._p.loader.main_bin.os

        if self.os != "cgc" and self.os != "unix":
            l.error("\"%s\" runs on an OS not supported by the tracer",
                    self.binary)
            raise TracerEnvironmentError

        # try to find the install base
        self.base = shellphish_qemu.qemu_base()

        try:
            self._check_qemu_install()
        except TracerEnvironmentError:
            self.base = os.path.join(self.base, "..", "..")
            self._check_qemu_install()

        return True

    def _check_qemu_install(self):
        '''
        check the install location of qemu
        '''

        if self.os == "cgc":
            self.tracer_qemu = "shellphish-qemu-cgc-tracer"
            qemu_platform = 'cgc-tracer'
        elif self.os == "unix":
            self.tracer_qemu = "shellphish-qemu-linux-%s" % self._p.arch.qemu_name
            qemu_platform = self._p.arch.qemu_name

        self.tracer_qemu_path = shellphish_qemu.qemu_path(qemu_platform)

        if not os.access(self.tracer_qemu_path, os.X_OK):
            if os.path.isfile(self.tracer_qemu_path):
                l.error("tracer-qemu-cgc is not executable")
                raise TracerEnvironmentError
            else:
                l.error("\"%s\" does not exist", self.tracer_qemu_path)
                raise TracerEnvironmentError

    def _cache_lookup(self):

        cache_tuple = self._cache_manager.cache_lookup()

        if cache_tuple is not None:
            # disable the cache_hook if we loaded from the cache
            receive.cache_hook = None

        return cache_tuple

# DYNAMIC TRACING

    def _address_in_binary(self, addr):
        '''
        determine if address @addr is in the binary being traced
        :param addr: the address to test
        :return: True if the address is in between the binary's min and
            max address
        '''
        mb = self._p.loader.main_bin
        return mb.get_min_addr() <= addr and addr < mb.get_max_addr()

    def _current_bb(self):
        try:
            self.trace[self.bb_cnt]
        except IndexError:
            if self.crash_mode:
                return None
            else:
                raise TracerDynamicTraceOOBError

    def dynamic_trace(self, stdout_file=None):
        '''
        accumulate a basic block trace using qemu
        '''

        lname = tempfile.mktemp(dir="/dev/shm/", prefix="tracer-log-")
        args = [self.tracer_qemu_path]

        if self.seed is not None:
            args += ["-seed", self.seed]

        # if the binary is CGC we'll also take this oppurtunity to read in the magic page
        if self.os == 'cgc':
            mname = tempfile.mktemp(dir="/dev/shm/", prefix="tracer-magic-")
            args += ["-magicdump", mname]

        args += ["-d", "exec", "-D", lname, self.binary]

        with open('/dev/null', 'wb') as devnull:
            stdout_f = devnull
            if stdout_file is not None:
                stdout_f = open(stdout_file, 'wb')

            # we assume qemu with always exit and won't block
            if self.pov_file is None:
                l.info("tracing as raw input")
                p = subprocess.Popen(
                        args,
                        stdin=subprocess.PIPE,
                        stdout=stdout_f,
                        stderr=devnull)
                _, _ = p.communicate(self.input)
            else:
                l.info("tracing as pov file")
                in_s, out_s = socket.socketpair()
                p = subprocess.Popen(
                        args,
                        stdin=in_s,
                        stdout=stdout_f,
                        stderr=devnull)
                for write in self.pov_file.writes:
                    out_s.send(write)
                    time.sleep(.01)
            ret = p.wait()
            # did a crash occur?
            if ret < 0:
                if abs(ret) == signal.SIGSEGV or abs(ret) == signal.SIGILL:
                    l.info("input caused a crash (signal %d)\
                            during dynamic tracing", abs(ret))
                    l.info("entering crash mode")
                    self.crash_mode = True

            if stdout_file is not None:
                stdout_f.close()

        with open(lname, 'rb') as f:
            trace = f.read()

        addrs = [int(v.split('[')[1].split(']')[0], 16)
                 for v in trace.split('\n')
                 if v.startswith('Trace')]

        # Find where qemu loaded the binary. Primarily for PIE
        self.qemu_base_addr = int(trace.split("start_code")[1].split("\n")[0],16)

        # grab the faulting address
        if self.crash_mode:
            self.crash_addr = int(
                    trace.split('\n')[-2].split('[')[1].split(']')[0],
                    16)

        if self.os == "cgc":
            with open(mname) as f:
                self._magic_content = f.read()

            a_mesg = "magic content read from QEMU improper size, should be a page in length"
            assert len(self._magic_content) == 0x1000, a_mesg

            os.remove(mname)

        os.remove(lname)

        return addrs

# SYMBOLIC TRACING

    def _preconstrain_state(self, entry_state):
        '''
        preconstrain the entry state to the input
        '''

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
        '''
        preconstrain the data in the flag page
        '''
        if not self.preconstrain_flag:
            return

        self._magic_content = self._magic_content
        for b in range(0x1000):
            v = flag_bytes[b]
            b_bvv = entry_state.se.BVV(self._magic_content[b])
            c = v == b_bvv
            self.variable_map[list(flag_bytes[b].variables)[0]] = c
            self.preconstraints.append(c)
            if so.REPLACEMENT_SOLVER in entry_state.options:
                entry_state.se._solver.add_replacement(v, b_bvv, invalidate_cache=False)

    def _set_cgc_simprocedures(self):
        for symbol in self.simprocedures:
            simuvex.SimProcedures['cgc'][symbol] = self.simprocedures[symbol]

    def _set_linux_simprocedures(self, project):
        for symbol in self.simprocedures:
            project.hook_symbol(
                    symbol,
                    self.simprocedures[symbol])

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

    def _prepare_paths(self):
        '''
        prepare initial paths
        '''

        if self.os == "cgc":

            cache_tuple = self._cache_lookup()
            pg = None
            # if we're restoring from a cache, we preconstrain
            if cache_tuple is not None:
                bb_cnt, self.cgc_flag_bytes, state, claripy.ast.base.var_counter = cache_tuple
                pg = self._cgc_prepare_paths(state)
                self._preconstrain_state(state)
                self.bb_cnt = bb_cnt
            else: # if we're not restoring from a cache, the cacher will preconstrain
                pg = self._cgc_prepare_paths()

            return pg

        elif self.os == "unix":
            return self._linux_prepare_paths()

        raise TracerEnvironmentError(
                "unsupport OS \"%s\" called _prepare_paths",
                self.os)

    def _prepare_dialogue(self):
        '''
        prepare a simdialogue entry for stdin
        '''

        s = simuvex.storage.file.SimDialogue("/dev/stdin")
        for write in self.pov_file.writes:
            s.add_dialogue_entry(len(write))

        return {'/dev/stdin': s}

    def _cgc_prepare_paths(self, state=None):
        '''
        prepare the initial paths for CGC binaries
        :param state: optional state to use instead of preparing a fresh one
        '''

        # FixedRandom, FixedInReceive, and FixedOutTransmit always are applied as defaults
        simuvex.SimProcedures['cgc']['random'] = FixedRandom
        simuvex.SimProcedures['cgc']['receive'] = FixedInReceive
        simuvex.SimProcedures['cgc']['transmit'] = FixedOutTransmit

        # if we're in crash mode we want the authentic system calls
        if not self.crash_mode:
            self._set_cgc_simprocedures()

        project = angr.Project(self.binary)

        self._set_hooks(project)

        if not self.pov:
            fs = {'/dev/stdin': simuvex.storage.file.SimFile(
                "/dev/stdin", "r",
                size=self.input_max_size)}

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
                l.debug("unicorn tracing enabled")
            except AttributeError:
                pass

            self.remove_options |= so.simplification | set(so.LAZY_SOLVES) | set(so.SUPPORT_FLOATING_POINT)
            self.add_options |= options
            entry_state = project.factory.entry_state(
                fs=fs,
                add_options=self.add_options,
                remove_options=self.remove_options)

            csr = entry_state.unicorn.cooldown_symbolic_registers
            entry_state.unicorn.concretization_threshold_registers = 25000 / csr
            entry_state.unicorn.concretization_threshold_memory = 25000 / csr
        else:
            # hookup the new files
            for name in fs:
                fs[name].set_state(state)
                for fd in state.posix.files:
                    if state.posix.files[fd].name == name:
                        state.posix.files[fd] = fs[name]
                        break

            state.scratch.executed_block_count = 0

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
            entry_state.inspect.b('syscall', when=simuvex.BP_BEFORE, action=self.syscall)
        entry_state.inspect.b('path_step', when=simuvex.BP_AFTER,
                action=self.check_stack)
        pg = project.factory.path_group(
            entry_state,
            immutable=True,
            save_unsat=True,
            hierarchy=False,
            save_unconstrained=self.crash_mode)

        pg.use_technique(angr.exploration_techniques.Oppologist())
        l.info("oppologist enabled")

        return pg

    def syscall(self, state):
        syscall_addr = state.se.any_int(state.ip)
        # 0xa000008 is terminate, which we exclude from syscall statistics.
        if syscall_addr != 0xa000008:
            args = s_cc.SyscallCC['X86']['CGC'](self._p.arch).get_args(state, 4)
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

    def _linux_prepare_paths(self):
        '''
        prepare the initial paths for Linux binaries
        '''

        # Only requesting custom base if this is a PIE
        if self._p.loader.main_bin.pic:
            project = angr.Project(self.binary,load_options={'main_opts': {'custom_base_addr': self.qemu_base_addr }},exclude_sim_procedures_list=self.exclude_sim_procedures_list)
        else:
            project = angr.Project(self.binary,exclude_sim_procedures_list=self.exclude_sim_procedures_list)

        if not self.crash_mode:
            self._set_linux_simprocedures(project)

        self._set_hooks(project)

        # fix stdin to the size of the input being traced
        fs = {'/dev/stdin': simuvex.storage.file.SimFile(
            "/dev/stdin", "r",
            size=self.input_max_size)}

        options = set()
        options.add(so.CGC_ZERO_FILL_UNCONSTRAINED_MEMORY)
        options.add(so.BYPASS_UNSUPPORTED_SYSCALL)
        options.add(so.REPLACEMENT_SOLVER)
        options.add(so.UNICORN)
        options.add(so.UNICORN_HANDLE_TRANSMIT_SYSCALL)
        if self.crash_mode:
            options.add(so.TRACK_ACTION_HISTORY)

        self.remove_options |= so.simplification
        self.add_options |= options
        entry_state = project.factory.full_init_state(
                fs=fs,
                concrete_fs=True,
                chroot=self.chroot,
                add_options=self.add_options,
                remove_options=self.remove_options,
                args=self.argv)

        if self.preconstrain_input:
            self._preconstrain_state(entry_state)

        # increase size of libc limits
        entry_state.libc.buf_symbolic_bytes = 1024
        entry_state.libc.max_str_len = 1024

        pg = project.factory.path_group(
                entry_state,
                immutable=True,
                save_unsat=True,
                hierarchy=False,
                save_unconstrained=self.crash_mode)

        # Step forward until we catch up with QEMU
        if pg.active[0].addr != self.trace[0]:
            pg = pg.explore(find=project.entry)
            pg = pg.drop(stash="unsat")
            pg = pg.unstash(from_stash="found",to_stash="active")

        # don't step here, because unlike CGC we aren't going to be starting
        # anywhere but the entry point
        return pg

    def _addr_in_plt(self,addr):
        """
        Check if an address is inside the ptt section
        """
        plt = self._p.loader.main_bin.sections_map['.plt']
        return addr >= plt.min_addr and addr <= plt.max_addr
