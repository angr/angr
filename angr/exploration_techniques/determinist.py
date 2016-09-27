
import logging
from collections import defaultdict

import networkx

import simuvex

from ..knowledge_base import KnowledgeBase
from . import ExplorationTechnique

l = logging.getLogger("angr.exploration_techniques.determinist")


class BaseGoal(object):
    def __init__(self, sort):
        self.sort = sort

    def __repr__(self):
        return "<TargetCondition %s>" % self.sort

    #
    # Public methods
    #

    def check(self, cfg, path, peek_blocks):
        """

        :param angr.analyses.CFGAccurate cfg:   An instance of CFGAccurate.
        :param angr.Path path:                  The path to check.
        :param int peek_blocks:                 Number of blocks to peek ahead from the current point.
        :return: True if we can determine that this condition is definitely satisfiable if the path is taken, False
                otherwise.
        :rtype: bool
        """

        raise NotImplementedError()

    #
    # Private methods
    #

    def _get_cfg_node(self, cfg, path):
        """
        Get the CFGNode object on the control flow graph given an angr path.

        :param angr.analyses.CFGAccurate cfg:   An instance of CFGAccurate.
        :param angr.Path path:                  The current path.
        :return: A CFGNode instance if the node exists, or None if the node cannot be found.
        :rtype: CFGNode or None
        """

        call_stack_suffix = path.callstack.stack_suffix(cfg.context_sensitivity_level)
        is_syscall = path.jumpkind is not None and path.jumpkind.startswith('Ijk_Sys')

        continue_at = None
        if cfg.project.is_hooked(path.addr) and \
                cfg.project.hooked_by(path.addr) is simuvex.s_procedure.SimProcedureContinuation:
            continue_at = path.state.procedure_data.callstack[-1][1]

        simrun_key = cfg._generate_simrun_key(call_stack_suffix, path.addr,
                                              is_syscall, continue_at=continue_at
                                              )

        if cfg.get_node(simrun_key) is None:
            import ipdb; ipdb.set_trace()

        return cfg.get_node(simrun_key)

    def _dfs_edges(self, graph, source, max_steps=None):
        """
        Perform a depth-first search on the given DiGraph, with a limit on maximum steps.

        :param networkx.DiGraph graph:  The graph to traverse.
        :param Any source:              The source to begin traversal.
        :param int max_steps:           Maximum steps of the traversal, or None if not limiting steps.
        :return: An iterator of edges.
        """

        if max_steps is None:
            yield networkx.dfs_edges(graph, source)

        else:
            steps_map = defaultdict(int)
            traversed = { source }
            stack = [ source ]

            while stack:
                src = stack.pop()
                for dst in graph.successors(src):
                    if dst in traversed:
                        continue
                    traversed.add(dst)

                    dst_steps = max(steps_map[src] + 1, steps_map[dst])

                    if dst_steps > max_steps:
                        continue

                    yield src, dst

                    steps_map[dst] = dst_steps
                    stack.append(dst)


class ExecuteAddressGoal(BaseGoal):
    def __init__(self, addr):
        super(ExecuteAddressGoal, self).__init__('execute_address')

        self.addr = addr

    def __repr__(self):
        return "<ExecuteAddressCondition targeting %#x>" % self.addr

    def check(self, cfg, path, peek_blocks):
        """
        Check if the specified address will be executed

        :param cfg:
        :param path:
        :param int peek_blocks:
        :return:
        :rtype: bool
        """

        # Get the current CFGNode from the CFG
        node = self._get_cfg_node(cfg, path)

        if node is None:
            # Umm it doesn't exist on the control flow graph - why?
            l.error('Failed to find CFGNode for path %s on the control flow graph.', path)
            return False

        # crawl the graph to see if we can reach the target address next
        for src, dst in self._dfs_edges(cfg.graph, node, max_steps=peek_blocks):
            if src.addr == self.addr or dst.addr == self.addr:
                l.debug("Path %s will reach %#x.", path, self.addr)
                if path.addr == 0x4005ca:
                    import ipdb; ipdb.set_trace()
                return True

        l.debug('Path %s will not reach %#x.', path, self.addr)
        return False


class CallFunctionGoal(BaseGoal):
    def __init__(self, function, arguments):
        super(CallFunctionGoal, self).__init__('function_call')

        self.function = function
        self.arguments = arguments

    def __repr__(self):
        return "<FunctionCallCondition over %s>" % self.function


class Determinist(ExplorationTechnique):
    """
    An exploration technique for directed symbolic execution.

    A control flow graph (using CFGAccurate) is built and refined during symbolic execution. Each time the execution
    reaches a block that is outside of the CFG, the CFG recovery will be triggered with that state, with a maximum
    recovery depth (100 by default). If we see a basic block during path stepping that is not yet in the control flow
    graph, we go back to control flow graph recovery and "peek" more blocks forward.

    When stepping a path group, all paths are categorized into three different categories:
    - Might reach the destination within the peek depth. Those paths are prioritized.
    - Will not reach the destination within the peek depth. Those paths are de-prioritized. However, there is a little
      chance for those paths to be explored as well in order to prevent over-fitting.
    """

    def __init__(self, peek_blocks=100, peek_functions=5, goals=None):
        """
        Constructor.
        """

        super(ExplorationTechnique, self).__init__()

        self._peek_blocks = peek_blocks
        self._peek_functions = peek_functions
        self._goals = goals if goals is not None else [ ]

        self._cfg = None
        self._cfg_kb = None

    def step(self, pg, stash, **kwargs):
        """

        :param pg:
        :param stash:
        :param kwargs:
        :return:
        """

        # make sure all current blocks are in the CFG
        self._peek_forward(pg)

        # categorize all paths in the path group
        self._categorize_paths(pg)

        # step all active paths forward
        return pg.step()

    def add_goal(self, goal):
        """
        Add a goal.

        :param BaseGoal goal: The goal to add.
        :return: None
        """

        self._goals.append(goal)

    #
    # Private methods
    #

    def _peek_forward(self, pg):
        """
        Make sure all current basic block on each path shows up in the CFG. For blocks that are not in the CFG, start
        CFG recovery from them with a maximum basic block depth of 100.

        :param pg:
        :return:
        """

        if self._cfg is None:

            starts = [ p.state for p in pg.active ]
            self._cfg_kb = KnowledgeBase(self.project, self.project.loader.main_bin)

            self._cfg = self.project.analyses.CFGAccurate(kb=self._cfg_kb, starts=starts, max_steps=self._peek_blocks)

        else:

            starts = [ p.state for p in pg.active ]

            self._cfg.resume(starts=starts, max_steps=self._peek_blocks)

    def _categorize_paths(self, pg):
        """
        Categorize all paths into two different groups: reaching the destination within the peek depth, and not
        reaching the destination within the peek depth.

        :param PathGroup pg:    The path group that contains paths. All active paths (path belonging to "active" stash)
                                are subjected to categorization.
        :return:                The categorized path group.
        :rtype:                 angr.PathGroup
        """

        past_active_paths = len(pg.active)
        # past_deprioritized_paths = len(pg.deprioritized)

        pg.stash(
            filter_func=lambda p: all(not goal.check(self._cfg, p, peek_blocks=self._peek_blocks) for goal in self._goals),
            from_stash='active',
            to_stash='tmp',
        )

        if not pg.active:
            # active paths are empty - none of our existing paths will reach the target for sure
            # take back all deprioritized paths
            pg.stash(from_stash='tmp', to_stash='active')

        else:
            # TODO: pick some paths from depriorized stash to active stash to avoid overfitting
            pass

        pg.stash(from_stash='tmp', to_stash='deprioritized')

        active_paths = len(pg.active)
        # deprioritized_paths = len(pg.deprioritized)

        l.debug('%d/%d active paths are deprioritized.', past_active_paths - active_paths, past_active_paths)

        return pg
