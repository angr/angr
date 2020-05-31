import logging

from . import ExplorationTechnique
from ..knowledge_base import KnowledgeBase
from ..knowledge_plugins.functions import Function


l = logging.getLogger(name=__name__)


class LoopSeer(ExplorationTechnique):
    """
    This exploration technique monitors exploration and maintains all
    loop-related data (well, currently it is just the loop trip counts, but feel
    free to add something else).
    """

    def __init__(self, cfg=None, functions=None, loops=None, use_header=False,
                 bound=None, bound_reached=None, discard_stash='spinning',
                 limit_concrete_loops=True):
        """
        :param cfg:             Normalized CFG is required.
        :param functions:       Function(s) containing the loop(s) to be analyzed.
        :param loops:           Loop(s) to be analyzed.
        :param use_header:      Whether to use header based trip counter to compare with the bound limit.
        :param bound:           Limit the number of iteration a loop may be executed.
        :param bound_reached:   If provided, should be a function that takes a SimulationManager and returns
                                a SimulationManager. Will be called when loop execution reach the given bound.
                                Default to moving states that exceed the loop limit to a discard stash.
        :param discard_stash:   Name of the stash containing states exceeding the loop limit.
        :param limit_concrete_loops: If False, do not limit a loop back-edge if it is the only successor
                                (Defaults to True to maintain the original behavior)
        """

        super(LoopSeer, self).__init__()
        self.cfg = cfg
        self.functions = functions
        self.bound = bound
        self.bound_reached = bound_reached
        self.discard_stash = discard_stash
        self.use_header = use_header
        self.limit_concrete_loops = limit_concrete_loops
        self.loops = {}
        self.cut_succs = []
        if type(loops) is Loop:
            loops = [loops]

        if type(loops) in (list, tuple) and all(type(l) is Loop for l in loops):
            for loop in loops:
                if loop.entry_edges:
                    self.loops[loop.entry_edges[0][0].addr] = loop

        elif loops is not None:
            raise TypeError("Invalid type for 'loops' parameter!")

    def setup(self, simgr):
        if self.cfg is None:
            cfg_kb = KnowledgeBase(self.project)
            self.cfg = self.project.analyses.CFGFast(kb=cfg_kb, normalize=True)
        elif not self.cfg.normalized:
            l.warning("LoopSeer must use a normalized CFG. Normalizing the provided CFG...")
            self.cfg.normalize()

        funcs = None
        if type(self.functions) in (str, int, Function):
            funcs = [self._get_function(self.functions)]

        elif type(self.functions) in (list, tuple) and all(type(f) in (str, int, Function) for f in self.functions):
            funcs = []
            for f in self.functions:
                func = self._get_function(f)
                if func is not None:
                    funcs.append(func)
            funcs = None if not funcs else funcs

        elif self.functions is not None:
            raise TypeError("Invalid type for 'functions' parameter!")

        if not self.loops:
            loop_finder = self.project.analyses.LoopFinder(kb=self.cfg.kb, normalize=True, functions=funcs)

            for loop in loop_finder.loops:
                if loop.entry_edges:
                    entry = loop.entry_edges[0][0]
                    self.loops[entry.addr] = loop

    def filter(self, simgr, state, **kwargs):
        if state in self.cut_succs:
            self.cut_succs.remove(state)
            return self.discard_stash
        else:
            return simgr.filter(state, **kwargs)

    def successors(self, simgr, state, **kwargs):
        node = self.cfg.model.get_any_node(state.addr)
        if node is not None:
            kwargs['num_inst'] = min(kwargs.get('num_inst', float('inf')), len(node.instruction_addrs))
        succs = simgr.successors(state, **kwargs)


        # Edge case: When limiting concrete loops, we may not want to do so
        # via the header.  If there is a way out of the loop, and we can
        # chose not to take it (e.g., the loop is not concrete), increase the trip count
        at_loop_exit = False
        for succ_state in succs.successors:
            if succ_state.loop_data.current_loop:
                if succ_state.addr in succ_state.loop_data.current_loop[-1][1]:
                    at_loop_exit = True
        for succ_state in succs.successors:
            # Processing a currently running loop
            if succ_state.loop_data.current_loop:
                loop = succ_state.loop_data.current_loop[-1][0]
                header = loop.entry.addr
                if succ_state.addr == header:
                    continue_addrs = [e[0].addr for e in loop.continue_edges]
                    # If there's only one successor, the loop is "concrete"
                    # We may wish not to cut loops that are concrete, as this can dead-end
                    # the path prematurely, even when there won't be state explosion.
                    if self.limit_concrete_loops or len(succs.successors) > 1:
                        if succ_state.history.addr in continue_addrs:
                            succ_state.loop_data.back_edge_trip_counts[succ_state.addr][-1] += 1
                        succ_state.loop_data.header_trip_counts[succ_state.addr][-1] += 1
                elif succ_state.addr in succ_state.loop_data.current_loop[-1][1]:
                    succ_state.loop_data.current_loop.pop()
                elif at_loop_exit and self.limit_concrete_loops:
                    # We're not at the header, but we're where we exit the loop
                    # NOTE: this only matters if you want to not limit concrete loops
                    if not self.limit_concrete_loops and len(succs.successors) > 1:
                        succ_state.loop_data.back_edge_trip_counts[succ_state.addr][-1] += 1
                if self.bound is not None and succ_state.loop_data.current_loop:
                    counts = 0
                    if self.use_header:
                        counts = succ_state.loop_data.header_trip_counts[header][-1]
                    else:
                        if succ_state.addr in succ_state.loop_data.back_edge_trip_counts:
                            counts = succ_state.loop_data.back_edge_trip_counts[succ_state.addr][-1]
                    if counts > self.bound:
                        if self.bound_reached is not None:
                            simgr = self.bound_reached(simgr)
                        else:
                            # Remove the state from the successors object
                            self.cut_succs.append(succ_state)


                l.debug("%s back edge based trip counts %s", state, state.loop_data.back_edge_trip_counts)
                l.debug("%s header based trip counts %s", state, state.loop_data.header_trip_counts)

            # Loop entry detected. This test is put here because in case of
            # nested loops, we want to handle the outer loop before proceeding
            # the inner loop.
            if succ_state.addr in self.loops:
                loop = self.loops[succ_state.addr]
                header = loop.entry.addr
                exits = [e[1].addr for e in loop.break_edges]

                succ_state.loop_data.back_edge_trip_counts[header].append(0)
                # If we are not limiting concrete loops, we also consider
                # trip counts at the possible exits
                if not self.limit_concrete_loops:
                    for node in loop.body_nodes:
                        succ_state.loop_data.back_edge_trip_counts[node.addr].append(0)
                succ_state.loop_data.header_trip_counts[header].append(0)
                succ_state.loop_data.current_loop.append((loop, exits))
        return succs
    def _get_function(self, func):
        f = None
        if type(func) is str:
            f = self.cfg.kb.functions.function(name=func)
            if f is None:
                l.warning("Function '%s' doesn't exist in the CFG. Skipping...", func)

        elif type(func) is int:
            f = self.cfg.kb.functions.function(addr=func)
            if f is None:
                l.warning("Function at 0x%x doesn't exist in the CFG. Skipping...", func)

        elif type(func) is Function:
            f = func

        return f

from ..analyses.loopfinder import Loop
