import logging

from . import ExplorationTechnique
from ..analyses.loopfinder import Loop
from ..knowledge_base import KnowledgeBase
from ..knowledge_plugins.functions import Function


l = logging.getLogger("angr.exploration_techniques.loop_seer")


class LoopSeer(ExplorationTechnique):
    """
    This exploration technique monitors exploration and maintains all
    loop-related data (well, currently it is just the loop trip counts, but feel
    free to add something else).
    """

    def __init__(self, cfg=None, functions=None, loops=None, bound=None, bound_reached=None, discard_stash='spinning'):
        """
        :param cfg:             Normalized CFG is required.
        :param functions:       Function(s) containing the loop(s) to be analyzed.
        :param loops:           Loop(s) to be analyzed.
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

        self.loops = {}

        if type(loops) is Loop:
            loops = [loops]

        if type(loops) in (list, tuple) and all(type(l) is Loop for l in loops):
            for loop in loops:
                self.loops[loop.entry_edges[0][0].addr] = loop

        elif loops is not None:
            raise TypeError('What type of loop is it?')

    def setup(self, simgr):
        if self.cfg is None:
            cfg_kb = KnowledgeBase(self.project, self.project.loader.main_object)
            self.cfg = self.project.analyses.CFGFast(kb=cfg_kb, normalize=True)
        elif not self.cfg.normalized:
            l.warning("LoopSeer uses normalized CFG. Recomputing the CFG...")
            self.cfg.normalize()

        if type(self.functions) is str:
            func = [self.cfg.kb.functions.function(name=self.functions)]

        elif type(self.functions) is int:
            func = [self.cfg.kb.functions.function(addr=self.functions)]

        elif type(self.functions) is Function:
            func = [self.functions]

        elif type(self.functions) in (list, tuple):
            func = []
            for f in self.functions:
                if type(f) is str:
                    func.append(self.cfg.kb.functions.function(name=f))

                elif type(f) is int:
                    func.append(self.cfg.kb.functions.function(addr=f))

                elif type(f) is Function:
                    func.append(f)

                else:
                    raise TypeError("What type of function is it?")
        elif self.functions is None:
            func = None

        else:
            raise TypeError("What type of function is it?")

        if not self.loops or func is not None:
            loop_finder = self.project.analyses.LoopFinder(kb=self.cfg.kb, normalize=True, functions=func)

            for loop in loop_finder.loops:
                entry = loop.entry_edges[0][0]
                self.loops[entry.addr] = loop

    def step(self, simgr, stash='active', **kwargs):
        kwargs['successor_func'] = self.normalized_step

        for state in simgr.stashes[stash]:
            # Processing a currently running loop
            if state.loop_data.current_loop:
                loop = state.loop_data.current_loop[-1][0]
                header = loop.entry.addr

                if state.addr == header:
                    state.loop_data.trip_counts[state.addr][-1] += 1

                elif state.addr in state.loop_data.current_loop[-1][1]:
                    # This is for unoptimized while/for loops.
                    #
                    # 0x10812: movs r3, #0          -> this block dominates the loop
                    # 0x10814: str  r3, [r7, #20]
                    # 0x10816: b    0x10868
                    # 0x10818: movs r3, #0          -> the real loop body starts here
                    # ...
                    # 0x10868: ldr  r3, [r7, #20]   -> the loop header is executed the first time without executing the loop body
                    # 0x1086a: cmp  r3, #3
                    # 0x1086c: ble  0x10818

                    back_edge_src = loop.continue_edges[0][0].addr
                    back_edge_dst = loop.continue_edges[0][1].addr
                    block = self.project.factory.block(back_edge_src)
                    if back_edge_src != back_edge_dst and back_edge_dst in block.instruction_addrs:
                        state.loop_data.trip_counts[header][-1] -= 1

                    state.loop_data.current_loop.pop()

                if self.bound is not None:
                    if state.loop_data.trip_counts[header][-1] > self.bound:
                        if self.bound_reached is not None:
                            simgr = self.bound_reached(simgr)
                        else:
                            simgr.stashes[stash].remove(state)
                            simgr.stashes[self.discard_stash].append(state)

                l.debug("%s trip counts %s", state, state.loop_data.trip_counts)

            # Loop entry detected. This test is put here because in case of
            # nested loops, we want to handle the outer loop before proceeding
            # the inner loop.
            if state.addr in self.loops:
                loop = self.loops[state.addr]
                header = loop.entry.addr
                exits = [e[1].addr for e in loop.break_edges]

                state.loop_data.trip_counts[header].append(0)
                state.loop_data.current_loop.append((loop, exits))

        simgr.step(stash=stash, **kwargs)

        return simgr

    def normalized_step(self, state):
        node = self.cfg.get_any_node(state.addr)
        return state.step(num_inst=len(node.instruction_addrs) if node is not None else None)
