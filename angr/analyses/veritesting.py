import logging
from collections import defaultdict
from functools import cmp_to_key
from typing import Tuple

import networkx

from .. import SIM_PROCEDURES
from .. import options as o
from ..knowledge_base import KnowledgeBase
from ..errors import AngrError, AngrCFGError
from ..sim_manager import SimulationManager
from ..utils.graph import shallow_reverse
from . import Analysis, CFGEmulated

l = logging.getLogger(name=__name__)


class VeritestingError(Exception):
    pass


class CallTracingFilter:
    """
    Filter to apply during CFG creation on a given state and jumpkind to determine if it should be skipped at a certain
    depth
    """

    whitelist = {
        SIM_PROCEDURES["cgc"]["receive"],
        SIM_PROCEDURES["cgc"]["transmit"],
        SIM_PROCEDURES["posix"]["read"],
        SIM_PROCEDURES["libc"]["fgetc"],
        SIM_PROCEDURES["glibc"]["__ctype_b_loc"],
        SIM_PROCEDURES["libc"]["strlen"],
        SIM_PROCEDURES["libc"]["strcmp"],
        SIM_PROCEDURES["libc"]["atoi"],
    }

    cfg_cache = {}

    def __init__(self, project, depth, blacklist=None):
        self.project = project
        self.blacklist = [] if blacklist is None else blacklist
        self._skipped_targets = set()
        self.depth = depth

    def filter(self, call_target_state, jumpkind):
        """
        The call will be skipped if it returns True.

        :param call_target_state:   The new state of the call target.
        :param jumpkind:            The Jumpkind of this call.
        :returns:                   True if we want to skip this call, False otherwise.
        """

        ACCEPT = False
        REJECT = True

        l.debug("Filtering calling target %s", call_target_state.ip)

        # Currently we always skip the call, unless the target function satisfies one of the following conditions:
        # 1) It's a SimProcedure that are in the whitelist
        # 2) It's a function that has no loops, and no calls/syscalls,
        # 3) It's a function that has no loops, and only has calls to another function that will not be filtered out by
        #    this filter

        # Generate a CFG
        ip = call_target_state.ip

        if self.depth >= 5:
            l.debug("Rejecting target %s - too deep, depth is %d", ip, self.depth)
            return REJECT

        try:
            addr = call_target_state.solver.eval_one(ip)
        except (SimValueError, SimSolverModeError):
            self._skipped_targets.add(-1)
            l.debug("Rejecting target %s - cannot be concretized", ip)
            return REJECT

        # Is it in our blacklist?
        if addr in self.blacklist:
            self._skipped_targets.add(addr)
            l.debug("Rejecting target 0x%x - blacklisted", addr)
            return REJECT

        # If the target is a SimProcedure, is it on our whitelist?
        if self.project.is_hooked(addr) and type(self.project._sim_procedures[addr][0]) in CallTracingFilter.whitelist:
            # accept!
            l.debug("Accepting target 0x%x, jumpkind %s", addr, jumpkind)
            return ACCEPT

        # If it's a syscall, let's see if the real syscall is inside our whitelist
        if jumpkind.startswith("Ijk_Sys"):
            call_target_state.history.jumpkind = jumpkind
            successors_ = self.project.factory.successors(call_target_state)
            try:
                next_run = successors_.artifacts["procedure"]
            except KeyError:
                l.warning("CallTracingFilter.filter(): except artifacts['procedure'] in %s. Reject.", successors_)
                return REJECT

            if type(next_run) in CallTracingFilter.whitelist:
                # accept!
                l.debug("Accepting target 0x%x, jumpkind %s", addr, jumpkind)
                return ACCEPT
            else:
                # reject
                l.debug("Rejecting target 0x%x - syscall %s not in whitelist", addr, type(next_run))
                return REJECT

        cfg_key = (addr, jumpkind, self.project.filename)
        if cfg_key not in self.cfg_cache:
            new_blacklist = self.blacklist[::]
            new_blacklist.append(addr)
            tracing_filter = CallTracingFilter(self.project, depth=self.depth + 1, blacklist=new_blacklist)
            cfg = self.project.analyses[CFGEmulated].prep(kb=KnowledgeBase(self.project))(
                starts=((addr, jumpkind),),
                initial_state=call_target_state,
                context_sensitivity_level=0,
                call_depth=1,
                call_tracing_filter=tracing_filter.filter,
                normalize=True,
            )
            self.cfg_cache[cfg_key] = (cfg, tracing_filter)

            try:
                cfg.force_unroll_loops(1)
            except AngrCFGError:
                # Exceptions occurred during loop unrolling
                # reject
                l.debug("Rejecting target %#x - loop unrolling failed", addr)
                return REJECT

        else:
            l.debug("Loading CFG from CFG cache")
            cfg, tracing_filter = self.cfg_cache[cfg_key]

        if cfg._loop_back_edges:
            # It has loops!
            self._skipped_targets.add(addr)
            l.debug("Rejecting target 0x%x - it has loops", addr)
            return REJECT

        sim_procedures = [n for n in cfg.graph.nodes() if n.simprocedure_name is not None]
        for sp_node in sim_procedures:
            if not self.project.is_hooked(sp_node.addr):
                # This is probably a PathTerminator
                # Just skip it for now
                continue

            if self.project._sim_procedures[sp_node.addr].procedure not in CallTracingFilter.whitelist:
                self._skipped_targets.add(addr)
                l.debug("Rejecting target 0x%x - contains SimProcedures outside whitelist", addr)
                return REJECT

        if len(tracing_filter._skipped_targets):
            # Bummer
            self._skipped_targets.add(addr)
            l.debug("Rejecting target 0x%x - should be skipped", addr)
            return REJECT

        # accept!
        l.debug("Accepting target 0x%x, jumpkind %s", addr, jumpkind)
        return ACCEPT


class Veritesting(Analysis):
    """
    An exploration technique made for condensing chunks of code to single (nested) if-then-else constraints via CFG
    accurate to conduct Static Symbolic Execution SSE (conversion to single constraint)
    """

    # A cache for CFG we generated before
    cfg_cache = {}
    # Names of all stashes we will return from Veritesting
    all_stashes = ("successful", "errored", "deadended", "deviated", "unconstrained")

    def __init__(
        self,
        input_state,
        boundaries=None,
        loop_unrolling_limit=10,
        enable_function_inlining=False,
        terminator=None,
        deviation_filter=None,
    ):
        """
        SSE stands for Static Symbolic Execution, and we also implemented an extended version of Veritesting (Avgerinos,
        Thanassis, et al, ICSE 2014).

        :param input_state:              The initial state to begin the execution with.
        :param boundaries:               Addresses where execution should stop.
        :param loop_unrolling_limit:     The maximum times that Veritesting should unroll a loop for.
        :param enable_function_inlining: Whether we should enable function inlining and syscall inlining.
        :param terminator:               A callback function that takes a state as parameter. Veritesting will terminate
                                         if this function returns True.
        :param deviation_filter:         A callback function that takes a state as parameter. Veritesting will put the
                                         state into "deviated" stash if this function returns True.
        """
        block = self.project.factory.block(input_state.addr)
        branches = block.vex.constant_jump_targets_and_jumpkinds

        # if we are not at a conditional jump, just do a normal step
        if list(branches.values()) != ["Ijk_Boring", "Ijk_Boring"]:
            self.result, self.final_manager = False, None
            return

        # otherwise do a veritesting step

        self._input_state = input_state.copy()
        self._boundaries = boundaries if boundaries is not None else []
        self._loop_unrolling_limit = loop_unrolling_limit
        self._enable_function_inlining = enable_function_inlining
        self._terminator = terminator
        self._deviation_filter = deviation_filter

        # set up the cfg stuff
        self._cfg, self._loop_graph = self._make_cfg()
        self._loop_backedges = self._cfg._loop_back_edges
        self._loop_heads = {dst.addr for _, dst in self._loop_backedges}

        l.info("Static symbolic execution starts at %#x", self._input_state.addr)
        l.debug(
            "The execution will terminate at the following addresses: [ %s ]",
            ", ".join([hex(i) for i in self._boundaries]),
        )

        l.debug("A loop will be unrolled by a maximum of %d times.", self._loop_unrolling_limit)
        if self._enable_function_inlining:
            l.debug("Function inlining is enabled.")
        else:
            l.debug("Function inlining is disabled.")

        self.result, self.final_manager = self._veritesting()

    def _veritesting(self) -> Tuple[bool, SimulationManager]:
        """
        Perform static symbolic execution starting from the given point.
        :returns: tuple of the success/failure of veritesting and the subsequent SimulationManager after execution
        """

        s = self._input_state.copy()

        try:
            new_manager = self._execute_and_merge(s)

        except (ClaripyError, SimError, AngrError):
            if BYPASS_VERITESTING_EXCEPTIONS not in s.options:
                raise
            l.warning("Veritesting caught an exception.", exc_info=True)
            return False, SimulationManager(self.project, stashes={"deviated": [s]})

        except VeritestingError as ex:
            l.warning("Exception occurred: %s", str(ex))
            return False, SimulationManager(self.project, stashes={"deviated": [s]})

        l.info(
            "Returning new paths: (successful: %s, deadended: %s, errored: %s, deviated: %s)",
            len(new_manager.successful),
            len(new_manager.deadended),
            len(new_manager.errored),
            len(new_manager.deviated),
        )

        return True, new_manager

    def _execute_and_merge(self, state):
        """
        Symbolically execute the program in a static manner. The basic idea is that we look ahead by creating a CFG,
        then perform a _controlled symbolic exploration_ based on the CFG, one path at a time. The controlled symbolic
        exploration stops when it sees a branch whose both directions are all feasible, or it shall wait for a merge
        from another path.

        A basic block will not be executed for more than *loop_unrolling_limit* times. If that is the case, a new state
        will be returned.

        :param SimState state: The initial state to start the execution.
        :returns:         A list of new states.
        """

        # Find all merge points
        merge_points = self._get_all_merge_points(self._cfg, self._loop_graph)
        l.debug("Merge points: %s", [hex(i[0]) for i in merge_points])

        #
        # Controlled symbolic exploration
        #

        # Initialize the beginning state
        initial_state = state
        initial_state.globals["loop_ctrs"] = defaultdict(int)

        manager = SimulationManager(
            self.project,
            active_states=[initial_state],
            resilience=o.BYPASS_VERITESTING_EXCEPTIONS in initial_state.options,
        )

        # Initialize all stashes
        for stash in self.all_stashes:
            manager.stashes[stash] = []
        # immediate_dominators = cfg.immediate_dominators(cfg.get_any_node(ip_int))

        while manager.active:
            # Step one step forward
            l.debug("Steps %s with %d active states: [ %s ]", manager, len(manager.active), manager.active)

            # Apply self.deviation_func on every single active state, and move them to deviated stash if needed
            if self._deviation_filter is not None:
                manager.stash(filter_func=self._deviation_filter, from_stash="active", to_stash="deviated")

            # Mark all those paths that are out of boundaries as successful
            manager.stash(filter_func=self.is_overbound, from_stash="active", to_stash="successful")

            manager.step(successor_func=self._get_successors)

            if self._terminator is not None and self._terminator(manager):
                for p in manager.stashes[stash]:
                    self._unfuck(p)
                break

            # Stash all paths that we do not see in our CFG
            manager.stash(filter_func=self.is_not_in_cfg, to_stash="deviated")

            # Stash all paths that we do not care about
            manager.stash(
                filter_func=lambda state: (
                    state.history.jumpkind not in ("Ijk_Boring", "Ijk_Call", "Ijk_Ret", "Ijk_NoHook")
                    and not state.history.jumpkind.startswith("Ijk_Sys")
                ),
                to_stash="deadended",
            )

            if manager.deadended:
                l.debug("Now we have some deadended paths: %s", manager.deadended)

            # Stash all possible states that we should merge later
            for merge_point_addr, merge_point_looping_times in merge_points:
                manager.stash(
                    lambda s: s.addr == merge_point_addr,  # pylint:disable=cell-var-from-loop
                    to_stash="_merge_%x_%d" % (merge_point_addr, merge_point_looping_times),
                )

            # Try to merge a set of previously stashed paths, and then unstash them
            if not manager.active:
                manager = self._join_merge_points(manager, merge_points)
        if any(len(manager.stashes[stash_name]) for stash_name in self.all_stashes):
            # Remove all stashes other than errored or deadended
            for stash in list(manager.stashes):
                if stash not in self.all_stashes:
                    manager.drop(stash=stash)

            for stash in manager.stashes:
                manager.apply(self._unfuck, stash=stash)

        return manager

    def _join_merge_points(self, manager, merge_points):
        """
        Merges together the appropriate execution points and unstashes them from the intermidiate merge_x_y stashes to
        pruned (dropped), deadend or active stashes

        param SimulationManager manager:        current simulation context being stepped through
        param [(int, int)] merge_points: list of address and loop counters of execution points to merge
        returns SimulationManager:              new manager with edited stashes
        """
        merged_anything = False
        for merge_point_addr, merge_point_looping_times in merge_points:
            if merged_anything:
                break

            stash_name = "_merge_%x_%d" % (merge_point_addr, merge_point_looping_times)
            if stash_name not in manager.stashes:
                continue

            stash_size = len(manager.stashes[stash_name])
            if stash_size == 0:
                continue
            if stash_size == 1:
                l.info("Skipping merge of 1 state in stash %s.", stash_size)
                manager.move(stash_name, "active")
                continue

            # let everyone know of the impending disaster
            l.info("Merging %d states in stash %s", stash_size, stash_name)

            # Try to prune the stash, so unsatisfiable states will be thrown away
            manager.prune(from_stash=stash_name, to_stash="pruned")
            if "pruned" in manager.stashes and len(manager.pruned):
                l.debug("... pruned %d paths from stash %s", len(manager.pruned), stash_name)
            # Remove the pruned stash to save memory
            manager.drop(stash="pruned")

            # merge things callstack by callstack
            while len(manager.stashes[stash_name]):
                r = manager.stashes[stash_name][0]
                manager.move(
                    stash_name, "merge_tmp", lambda p: p.callstack == r.callstack  # pylint:disable=cell-var-from-loop
                )

                old_count = len(manager.merge_tmp)
                l.debug("... trying to merge %d states.", old_count)

                # merge the loop_ctrs
                new_loop_ctrs = defaultdict(int)
                for m in manager.merge_tmp:
                    for head_addr, looping_times in m.globals["loop_ctrs"].items():
                        new_loop_ctrs[head_addr] = max(looping_times, m.globals["loop_ctrs"][head_addr])

                manager.merge(stash="merge_tmp")
                for m in manager.merge_tmp:
                    m.globals["loop_ctrs"] = new_loop_ctrs

                new_count = len(manager.stashes["merge_tmp"])
                l.debug("... after merge: %d states.", new_count)

                merged_anything |= new_count != old_count

                if len(manager.merge_tmp) > 1:
                    l.warning("More than 1 state after Veritesting merge.")
                    manager.move("merge_tmp", "active")
                elif any(
                    loop_ctr >= self._loop_unrolling_limit + 1
                    for loop_ctr in manager.one_merge_tmp.globals["loop_ctrs"].values()
                ):
                    l.debug("... merged state is overlooping")
                    manager.move("merge_tmp", "deadended")
                else:
                    l.debug("... merged state going to active stash")
                    manager.move("merge_tmp", "active")

        return manager

    #
    # Path management
    #

    def is_not_in_cfg(self, s):
        """
        Returns if s.addr is not a proper node in our CFG.

        :param SimState s: The SimState instance to test.
        :returns bool: False if our CFG contains p.addr, True otherwise.
        """

        n = self._cfg.model.get_any_node(s.addr, is_syscall=s.history.jumpkind.startswith("Ijk_Sys"))
        if n is None:
            return True

        if n.simprocedure_name == "PathTerminator":
            return True

        return False

    def _get_successors(self, state):
        """
        Gets the successors to the current state by step, saves copy of state and finally stashes new unconstrained
        states to manager.

        :param SimState state:          Current state to step on from
        :returns SimSuccessors:         The SimSuccessors object
        """
        size_of_next_irsb = self._cfg.model.get_any_node(state.addr).size
        return self.project.factory.successors(state, size=size_of_next_irsb)

    def is_overbound(self, state):
        """
        Filter out all states that run out of boundaries or loop too many times.

        param SimState state: SimState instance to check
        returns bool:    True if outside of mem/loop_ctr boundary
        """

        ip = state.addr

        if ip in self._boundaries:
            l.debug("... terminating Veritesting due to overbound")
            return True

        try:
            # If the address is not in the list (which could mean it is
            # not at the top of a block), check directly in the blocks
            # (Blocks are repeatedly created for every check, but with
            # the IRSB cache in angr lifter it should be OK.)
            if set(self._boundaries).intersection(set(self.project.factory.block(ip).instruction_addrs)):
                return True
        except (AngrError, SimError):
            pass

        if (
            ip in self._loop_heads  # This is the beginning of the loop
            or state.history.jumpkind == "Ijk_Call"  # We also wanna catch recursive function calls
        ):
            state.globals["loop_ctrs"][ip] += 1
            if state.globals["loop_ctrs"][ip] >= self._loop_unrolling_limit + 1:
                l.debug("... terminating Veritesting due to overlooping")
                return True

        l.debug("... accepted")
        return False

    @staticmethod
    def _unfuck(s):
        """
        Deletes the loop counter from state's information dictionary

        :param SimState s: SimState instance to update
        :returns SimState: same SimState with deleted loop counter
        """
        del s.globals["loop_ctrs"]
        return s

    #
    # Merge point determination
    #

    def _make_cfg(self):
        """
        Builds a CFG from the current function.
        Saved in cfg_cache.

        returns (CFGEmulated, networkx.DiGraph): Tuple of the CFG and networkx representation of it
        """

        state = self._input_state
        ip_int = state.addr

        # if the cfg is cached, simply return the cached cfg
        cfg_key = (ip_int, state.history.jumpkind, self.project.filename)
        if cfg_key in self.cfg_cache:
            cfg, cfg_graph_with_loops = self.cfg_cache[cfg_key]
            return cfg, cfg_graph_with_loops

        if self._enable_function_inlining:
            call_tracing_filter = CallTracingFilter(self.project, depth=0)
            filter = call_tracing_filter.filter  # pylint:disable=redefined-builtin
        else:
            filter = None

        # To better handle syscalls, we make a copy of all registers if they are not symbolic
        cfg_initial_state = self.project.factory.blank_state(mode="fastpath")

        # FIXME: This is very hackish
        # FIXME: And now only Linux-like syscalls are supported
        if self.project.arch.name == "X86":
            if not state.solver.symbolic(state.regs.eax):
                cfg_initial_state.regs.eax = state.regs.eax
        elif self.project.arch.name == "AMD64":
            if not state.solver.symbolic(state.regs.rax):
                cfg_initial_state.regs.rax = state.regs.rax

        # generate the cfg and perform loop unrolling
        cfg = self.project.analyses[CFGEmulated].prep(kb=KnowledgeBase(self.project))(
            starts=((ip_int, state.history.jumpkind),),
            context_sensitivity_level=0,
            call_depth=1,
            call_tracing_filter=filter,
            initial_state=cfg_initial_state,
            normalize=True,
        )
        cfg_graph_with_loops = networkx.DiGraph(cfg.graph)
        cfg.force_unroll_loops(self._loop_unrolling_limit)

        # cache the generated cfg
        self.cfg_cache[cfg_key] = (cfg, cfg_graph_with_loops)

        return cfg, cfg_graph_with_loops

    @staticmethod
    def _post_dominate(reversed_graph, n1, n2):
        """
        Checks whether `n1` post-dominates `n2` in the *original* (not reversed) graph.

        :param networkx.DiGraph reversed_graph:  The reversed networkx.DiGraph instance.
        :param networkx.Node n1:                 Node 1.
        :param networkx.Node n2:                 Node 2.
        :returns bool:                           True/False.
        """

        ds = networkx.immediate_dominators(reversed_graph, n1)
        return n2 in ds

    def _get_all_merge_points(self, cfg, graph_with_loops):
        """
        Return all possible merge points in this CFG.

        :param CFGEmulated cfg: The control flow graph, which must be acyclic.
        :returns [(int, int)]:  A list of merge points (address and number of times looped).
        """

        graph = networkx.DiGraph(cfg.graph)
        reversed_cyclic_graph = shallow_reverse(graph_with_loops)

        # Remove all "FakeRet" edges
        fakeret_edges = [
            (src, dst) for src, dst, data in graph.edges(data=True) if data["jumpkind"] in ("Ijk_FakeRet", "Ijk_Exit")
        ]
        graph.remove_edges_from(fakeret_edges)

        # Remove all "FakeRet" edges from cyclic_graph as well
        fakeret_edges = [
            (src, dst)
            for src, dst, data in reversed_cyclic_graph.edges(data=True)
            if data["jumpkind"] in ("Ijk_FakeRet", "Ijk_Exit")
        ]
        reversed_cyclic_graph.remove_edges_from(fakeret_edges)

        # Perform a topological sort
        sorted_nodes = networkx.topological_sort(graph)

        nodes = [n for n in sorted_nodes if graph.in_degree(n) > 1 and n.looping_times == 0]

        # Reorder nodes based on post-dominance relations
        nodes = sorted(
            nodes,
            key=cmp_to_key(
                lambda n1, n2: (
                    1
                    if self._post_dominate(reversed_cyclic_graph, n1, n2)
                    else (-1 if self._post_dominate(reversed_cyclic_graph, n2, n1) else 0)
                )
            ),
        )

        return [(n.addr, n.looping_times) for n in nodes]


from angr.analyses import AnalysesHub

AnalysesHub.register_default("Veritesting", Veritesting)

from ..errors import SimValueError, SimSolverModeError, SimError
from ..sim_options import BYPASS_VERITESTING_EXCEPTIONS
from claripy import ClaripyError
