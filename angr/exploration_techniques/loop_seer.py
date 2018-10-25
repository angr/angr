import logging

from . import ExplorationTechnique
from ..knowledge_base import KnowledgeBase
from ..knowledge_plugins.functions import Function


l = logging.getLogger("angr.exploration_techniques.loop_seer")


class LoopSeer(ExplorationTechnique):
    """
    This exploration technique monitors exploration and maintains all
    loop-related data (well, currently it is just the loop trip counts, but feel
    free to add something else).
    """

    def __init__(self, cfg=None, functions=None, loops=None, use_header=False, bound=None, bound_reached=None, discard_stash='spinning'):
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
        """

        super(LoopSeer, self).__init__()
        self.cfg = cfg
        self.functions = functions
        self.bound = bound
        self.bound_reached = bound_reached
        self.discard_stash = discard_stash
        self.use_header = use_header

        self.loops = {}
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
            cfg_kb = KnowledgeBase(self.project, self.project.loader.main_object)
            self.cfg = self.project.analyses.CFGFast(kb=cfg_kb, normalize=True)
        elif not self.cfg.normalized:
            l.warning("LoopSeer uses normalized CFG. Recomputing the CFG...")
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

    def step(self, simgr, stash='active', **kwargs):
        for state in simgr.stashes[stash]:
            # Processing a currently running loop
            if state.loop_data.current_loop:
                loop = state.loop_data.current_loop[-1][0]
                header = loop.entry.addr

                if state.addr == header:
                    continue_addrs = [e[0].addr for e in loop.continue_edges]
                    if state.history.addr in continue_addrs:
                        state.loop_data.back_edge_trip_counts[state.addr][-1] += 1
                    state.loop_data.header_trip_counts[state.addr][-1] += 1

                elif state.addr in state.loop_data.current_loop[-1][1]:
                    state.loop_data.current_loop.pop()

                if self.bound is not None:
                    counts = state.loop_data.back_edge_trip_counts[header][-1] if not self.use_header else \
                             state.loop_data.header_trip_counts[header][-1]
                    if counts > self.bound:
                        if self.bound_reached is not None:
                            simgr = self.bound_reached(simgr)
                        else:
                            simgr.stashes[stash].remove(state)
                            simgr.stashes[self.discard_stash].append(state)

                l.debug("%s back edge based trip counts %s", state, state.loop_data.back_edge_trip_counts)
                l.debug("%s header based trip counts %s", state, state.loop_data.header_trip_counts)

            # Loop entry detected. This test is put here because in case of
            # nested loops, we want to handle the outer loop before proceeding
            # the inner loop.
            if state.addr in self.loops:
                loop = self.loops[state.addr]
                header = loop.entry.addr
                exits = [e[1].addr for e in loop.break_edges]

                state.loop_data.back_edge_trip_counts[header].append(0)
                state.loop_data.header_trip_counts[header].append(0)
                state.loop_data.current_loop.append((loop, exits))

        simgr.step(stash=stash, **kwargs)

        return simgr

    def successors(self, simgr, state, **kwargs):
        node = self.cfg.get_any_node(state.addr)
        if node is not None:
            kwargs['num_inst'] = min(kwargs.get('num_inst', float('inf')), len(node.instruction_addrs))
        return simgr.successors(state, **kwargs)

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
