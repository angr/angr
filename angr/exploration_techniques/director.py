
import logging
from collections import defaultdict

import networkx

import claripy

from ..sim_type import SimType, SimTypePointer, SimTypeChar, SimTypeString, SimTypeReg
from ..calling_conventions import DEFAULT_CC
from ..knowledge_base import KnowledgeBase
from ..errors import AngrDirectorError
from . import ExplorationTechnique

l = logging.getLogger(name=__name__)


class BaseGoal(object):

    REQUIRE_CFG_STATES = False

    def __init__(self, sort):
        self.sort = sort

    def __repr__(self):
        return "<TargetCondition %s>" % self.sort

    #
    # Public methods
    #

    def check(self, cfg, state, peek_blocks):
        """

        :param angr.analyses.CFGEmulated cfg:   An instance of CFGEmulated.
        :param angr.SimState state:             The state to check.
        :param int peek_blocks:                 Number of blocks to peek ahead from the current point.
        :return: True if we can determine that this condition is definitely satisfiable if the path is taken, False
                otherwise.
        :rtype: bool
        """

        raise NotImplementedError()

    def check_state(self, state):
        """
        Check if the current state satisfies the goal.

        :param angr.SimState state:                  The state to check.
        :return: True if it satisfies the goal, False otherwise.
        :rtype: bool
        """

        raise NotImplementedError()

    #
    # Private methods
    #

    @staticmethod
    def _get_cfg_node(cfg, state):
        """
        Get the CFGNode object on the control flow graph given an angr state.

        :param angr.analyses.CFGEmulated cfg:   An instance of CFGEmulated.
        :param angr.SimState state:             The current state.
        :return: A CFGNode instance if the node exists, or None if the node cannot be found.
        :rtype: CFGNode or None
        """

        call_stack_suffix = state.callstack.stack_suffix(cfg.context_sensitivity_level)
        is_syscall = state.history.jumpkind is not None and state.history.jumpkind.startswith('Ijk_Sys')

        block_id = cfg._generate_block_id(call_stack_suffix, state.addr, is_syscall)

        return cfg.get_node(block_id)

    @staticmethod
    def _dfs_edges(graph, source, max_steps=None):
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
    """
    A goal that prioritizes states reaching (or are likely to reach) certain address in some specific steps.
    """

    def __init__(self, addr):
        super(ExecuteAddressGoal, self).__init__('execute_address')

        self.addr = addr

    def __repr__(self):
        return "<ExecuteAddressCondition targeting %#x>" % self.addr

    def check(self, cfg, state, peek_blocks):
        """
        Check if the specified address will be executed

        :param cfg:
        :param state:
        :param int peek_blocks:
        :return:
        :rtype: bool
        """

        # Get the current CFGNode from the CFG
        node = self._get_cfg_node(cfg, state)

        if node is None:
            # Umm it doesn't exist on the control flow graph - why?
            l.error('Failed to find CFGNode for state %s on the control flow graph.', state)
            return False

        # crawl the graph to see if we can reach the target address next
        for src, dst in self._dfs_edges(cfg.graph, node, max_steps=peek_blocks):
            if src.addr == self.addr or dst.addr == self.addr:
                l.debug("State %s will reach %#x.", state, self.addr)
                return True

        l.debug('SimState %s will not reach %#x.', state, self.addr)
        return False

    def check_state(self, state):
        """
        Check if the current address is the target address.

        :param angr.SimState state: The state to check.
        :return: True if the current address is the target address, False otherwise.
        :rtype: bool
        """

        return state.addr == self.addr


class CallFunctionGoal(BaseGoal):
    """
    A goal that prioritizes states reaching certain function, and optionally with specific arguments.
    Note that constraints on arguments (and on function address as well) have to be identifiable on an accurate CFG.
    For example, you may have a CallFunctionGoal saying "call printf with the first argument being 'Hello, world'", and
    CFGEmulated must be able to figure our the first argument to printf is in fact "Hello, world", not some symbolic
    strings that will be constrained to "Hello, world" during symbolic execution (or simulation, however you put it).
    """

    REQUIRE_CFG_STATES = True

    def __init__(self, function, arguments):
        super(CallFunctionGoal, self).__init__('function_call')

        self.function = function
        self.arguments = arguments

        if self.arguments is not None:
            for arg in self.arguments:
                if arg is not None:
                    if len(arg) != 2:
                        raise AngrDirectorError('Each argument must be either None or a 2-tuple contains argument ' +
                                                'type and the expected value.'
                                                )

                    arg_type, expected_value = arg

                    if not isinstance(arg_type, SimType):
                        raise AngrDirectorError('Each argument type must be an instance of SimType.')

                    if isinstance(expected_value, claripy.ast.Base) and expected_value.symbolic:
                        raise AngrDirectorError('Symbolic arguments are not supported.')

        # TODO: allow user to provide an optional argument processor to process arguments

    def __repr__(self):
        return "<FunctionCallCondition over %s>" % self.function

    def check(self, cfg, state, peek_blocks):
        """
        Check if the specified function will be reached with certain arguments.

        :param cfg:
        :param state:
        :param peek_blocks:
        :return:
        """

        # Get the current CFGNode
        node = self._get_cfg_node(cfg, state)

        if node is None:
            l.error("Failed to find CFGNode for state %s on the control flow graph.", state)
            return False

        # crawl the graph to see if we can reach the target function within the limited steps
        for src, dst in self._dfs_edges(cfg.graph, node, max_steps=peek_blocks):
            the_node = None
            if src.addr == self.function.addr:
                the_node = src
            elif dst.addr == self.function.addr:
                the_node = dst

            if the_node is not None:
                if self.arguments is None:
                    # we do not care about arguments
                    return True

                else:
                    # check arguments
                    arch = state.arch
                    state = the_node.input_state
                    same_arguments = self._check_arguments(arch, state)

                    if same_arguments:
                        # all arguments are the same!
                        return True

        l.debug("SimState %s will not reach function %s.", state, self.function)
        return False

    def check_state(self, state):
        """
        Check if the specific function is reached with certain arguments

        :param angr.SimState state: The state to check
        :return: True if the function is reached with certain arguments, False otherwise.
        :rtype: bool
        """

        if state.addr == self.function.addr:
            arch = state.arch
            if self._check_arguments(arch, state):
                return True

        return False

    #
    # Private methods
    #

    def _check_arguments(self, arch, state):

        # TODO: add calling convention detection to individual functions, and use that instead of the
        # TODO: default calling convention of the platform

        cc = DEFAULT_CC[arch.name](arch)  # type: s_cc.SimCC

        for i, expected_arg in enumerate(self.arguments):
            if expected_arg is None:
                continue
            real_arg = cc.arg(state, i)

            expected_arg_type, expected_arg_value = expected_arg
            r = self._compare_arguments(state, expected_arg_type, expected_arg_value, real_arg)
            if not r:
                return False

        return True

    @staticmethod
    def _compare_arguments(state, arg_type, expected_value, real_value):
        """

        :param SimState state:
        :param simvuex.s_type.SimType arg_type:
        :param claripy.ast.Base expected_value:
        :param claripy.ast.Base real_value:
        :return:
        :rtype: bool
        """

        if real_value.symbolic:
            # we do not support symbolic arguments yet
            return False

        if isinstance(arg_type, SimTypePointer):
            # resolve the pointer and compare the content
            points_to_type = arg_type.pts_to

            if isinstance(points_to_type, SimTypeChar):
                # char *
                # perform a concrete string comparison
                ptr = real_value
                return CallFunctionGoal._compare_pointer_content(state, ptr, expected_value)

            else:
                l.error('Unsupported argument type %s in _compare_arguments(). Please bug Fish to implement.', arg_type)

        elif isinstance(arg_type, SimTypeString):
            # resolve the pointer and compare the content
            ptr = real_value
            return CallFunctionGoal._compare_pointer_content(state, ptr, expected_value)

        elif isinstance(arg_type, SimTypeReg):
            # directly compare the numbers
            return CallFunctionGoal._compare_integer_content(state, real_value, expected_value)

        else:
            l.error('Unsupported argument type %s in _compare_arguments(). Please bug Fish to implement.', arg_type)

        return False

    @staticmethod
    def _compare_pointer_content(state, ptr, expected):

        if isinstance(expected, str):
            # convert it to an AST
            expected = state.solver.BVV(expected)
        length = expected.size() // 8
        real_string = state.memory.load(ptr, length, endness='Iend_BE')

        if real_string.symbolic:
            # we do not support symbolic arguments
            return False

        return state.solver.eval(real_string) == state.solver.eval(expected)

    @staticmethod
    def _compare_integer_content(state, val, expected):

        # note that size difference does not matter - we only compare their concrete values

        if isinstance(val, claripy.ast.Base) and val.symbolic:
            # we do not support symboli arguments
            return False

        return state.solver.eval(val) == state.solver.eval(expected)


class Director(ExplorationTechnique):
    """
    An exploration technique for directed symbolic execution.

    A control flow graph (using CFGEmulated) is built and refined during symbolic execution. Each time the execution
    reaches a block that is outside of the CFG, the CFG recovery will be triggered with that state, with a maximum
    recovery depth (100 by default). If we see a basic block during state stepping that is not yet in the control flow
    graph, we go back to control flow graph recovery and "peek" more blocks forward.

    When stepping a simulation manager, all states are categorized into three different categories:

    - Might reach the destination within the peek depth. Those states are prioritized.
    - Will not reach the destination within the peek depth. Those states are de-prioritized. However, there is a little
      chance for those states to be explored as well in order to prevent over-fitting.
    """

    def __init__(self, peek_blocks=100, peek_functions=5, goals=None, cfg_keep_states=False,
                 goal_satisfied_callback=None, num_fallback_states=5):
        """
        Constructor.
        """

        super(Director, self).__init__()

        self._peek_blocks = peek_blocks
        self._peek_functions = peek_functions
        self._goals = goals if goals is not None else [ ]
        self._cfg_keep_states = cfg_keep_states
        self._goal_satisfied_callback = goal_satisfied_callback
        self._num_fallback_states = num_fallback_states

        self._cfg = None
        self._cfg_kb = None

    def step(self, simgr, stash='active', **kwargs):
        """

        :param simgr:
        :param stash:
        :param kwargs:
        :return:
        """

        # make sure all current blocks are in the CFG
        self._peek_forward(simgr)

        # categorize all states in the simulation manager
        self._categorize_states(simgr)

        if not simgr.active:
            # active states are empty - none of our existing states will reach the target for sure
            self._load_fallback_states(simgr)

        if simgr.active:
            # step all active states forward
            simgr = simgr.step(stash=stash)

        if not simgr.active:
            self._load_fallback_states(simgr)

        return simgr

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

    def _peek_forward(self, simgr):
        """
        Make sure all current basic block on each state shows up in the CFG. For blocks that are not in the CFG, start
        CFG recovery from them with a maximum basic block depth of 100.

        :param simgr:
        :return:
        """

        if self._cfg is None:

            starts = list(simgr.active)
            self._cfg_kb = KnowledgeBase(self.project)

            self._cfg = self.project.analyses.CFGEmulated(kb=self._cfg_kb, starts=starts, max_steps=self._peek_blocks,
                                                          keep_state=self._cfg_keep_states
                                                          )

        else:

            starts = list(simgr.active)

            self._cfg.resume(starts=starts, max_steps=self._peek_blocks)

    def _load_fallback_states(self, pg):
        """
        Load the last N deprioritized states will be extracted from the "deprioritized" stash and put to "active" stash.
        N is controlled by 'num_fallback_states'.

        :param SimulationManager pg: The simulation manager.
        :return: None
        """

        # take back some of the deprioritized states
        l.debug("No more active states. Load some deprioritized states to 'active' stash.")
        if 'deprioritized' in pg.stashes and pg.deprioritized:
            pg.active.extend(pg.deprioritized[-self._num_fallback_states : ])
            pg.stashes['deprioritized'] = pg.deprioritized[ : -self._num_fallback_states]

    def _categorize_states(self, simgr):
        """
        Categorize all states into two different groups: reaching the destination within the peek depth, and not
        reaching the destination within the peek depth.

        :param SimulationManager simgr:    The simulation manager that contains states. All active states (state belonging to "active" stash)
                                are subjected to categorization.
        :return:                The categorized simulation manager.
        :rtype:                 angr.SimulationManager
        """

        past_active_states = len(simgr.active)
        # past_deprioritized_states = len(simgr.deprioritized)

        for goal in self._goals:
            for p in simgr.active:
                if self._check_goals(goal, p):
                    if self._goal_satisfied_callback is not None:
                        self._goal_satisfied_callback(goal, p, simgr)

        simgr.stash(
            filter_func=lambda p: all(not goal.check(self._cfg, p, peek_blocks=self._peek_blocks) for goal in
                                      self._goals
                                      ),
            from_stash='active',
            to_stash='deprioritized',
        )

        if simgr.active:
            # TODO: pick some states from depriorized stash to active stash to avoid overfitting
            pass

        active_states = len(simgr.active)
        # deprioritized_states = len(simgr.deprioritized)

        l.debug('%d/%d active states are deprioritized.', past_active_states - active_states, past_active_states)

        return simgr

    def _check_goals(self, goal, state):  # pylint:disable=no-self-use
        """
        Check if the state is satisfying the goal.

        :param BaseGoal goal: The goal to check against.
        :param angr.SimState state: The state to check.
        :return: True if the state satisfies the goal currently, False otherwise.
        :rtype: bool
        """

        return goal.check_state(state)
