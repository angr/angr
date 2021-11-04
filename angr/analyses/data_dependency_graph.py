from __future__ import annotations  # Makes all type hints strings that aren't evaluated (helps with cyclical imports)

import logging
import networkx

from typing import TYPE_CHECKING

from claripy import BV
from claripy.bv import BVV
from . import Analysis
from ..state_plugins import SimActionData, SimActionObject

if TYPE_CHECKING:
    from typing import Optional, TYPE_CHECKING, List, Tuple, Union, Dict
    from .. import SimState

_l = logging.getLogger(name=__name__)


class DepNodeTypes:
    Memory = 1
    Register = 2
    # Integer = 3
    Unknown = 3


class BaseDepNode:
    """
    Base class for all nodes in a data-dependency graph
    """

    def __init__(self, type_: int, instruction_addr: int, uid: int):
        self._type = type_
        self._instruction_addr = instruction_addr
        self._uid = uid

    @property
    def ins_addr(self) -> int:
        return self._instruction_addr

    @property
    def uid(self) -> int:
        """
        Unique ID for SimAction, should not repeat (even between basic blocks)
        :return:
        """
        return self._uid

    @property
    def type(self) -> int:
        """
        Getter
        :return: An integer defined in DepNodeTypes, represents the subclass type of this DepNode.
        """
        return self._type

    def __repr__(self):
        raise NotImplementedError()

    def __eq__(self, other):
        raise NotImplementedError()

    def __hash__(self):
        return hash(self._type) ^ hash(self.ins_addr)


class VarDepNode(BaseDepNode):
    def __init__(self, type_: int, ins_addr: int, uid: int, reg: int, arch_name: str = ''):
        super(VarDepNode, self).__init__(type_, ins_addr, uid)
        self.reg = reg
        self.arch_name = arch_name

    def __repr__(self):
        inner = self.arch_name if self.arch_name else hex(self.reg)
        return f"RegDep[{inner}]@{hex(self.ins_addr)}:{self.uid}"

    def __eq__(self, other):
        return self.type == other.type and self.reg == other.reg

    def __hash__(self):
        return super(VarDepNode, self).__hash__() ^ hash(self.reg)


class MemDepNode(BaseDepNode):
    def __init__(self, type_: int, ins_addr: int, uid: int, addr: int):
        super(MemDepNode, self).__init__(type_, ins_addr, uid)
        self.addr = addr

    def __repr__(self):
        return f"MemDep[{hex(self.addr)}]@{hex(self.ins_addr)}:{self.uid}"

    def __eq__(self, other):
        return self.type == other.type and self.addr == other.addr

    def __hash__(self):
        return super(MemDepNode, self).__hash__() ^ hash(self.addr)


class IntDepNode(BaseDepNode):
    def __init__(self, type_: int, ins_addr: int, uid: int, value: int):
        super(IntDepNode, self).__init__(type_, ins_addr, uid)
        self.value = value

    def __repr__(self):
        return f"IntDep[{hex(self.value)}]@{hex(self.ins_addr)}:{self.uid}"

    def __eq__(self, other):
        return self.type == other.type and self.value == other.value

    def __hash__(self):
        return hash(self.type) ^ hash(self.value)


class DataDependencyGraphAnalysis(Analysis):
    """
    generates a proximity graph based off data-dependency.
    """

    def __init__(self, end_state: SimState, start_from):
        self._graph: Optional[networkx.DiGraph] = None
        self._end_state = end_state
        self._start_from = start_from
        self._canonical_graph_nodes: Dict[
            BaseDepNode, BaseDepNode] = dict()  # Maps a node to itself for lookup purposes
        self._actions: List[SimActionData] = []

        self._work()

    @property
    def graph(self) -> Optional[networkx.DiGraph]:
        return self._graph

    def _pop(self) -> Optional[SimActionData]:
        """
        Safely pops the first action, if it exists.
        """
        return self._actions.pop(0) if self._actions else None

    def _peek(self, idx: int = 0) -> Optional[SimActionData]:
        """
        Safely returns the first action, if it exists, without removing it

        :param idx: Index to peek at, default 0
        """
        return self._actions[idx] if len(self._actions) > idx else None

    def _peek_type(self) -> str:
        """
        Safely returns the type of the first action, if it exists, otherwise ''
        """
        return self._actions[0].type if self._actions else ''

    def _peek_action(self) -> str:
        """
        Safely returns the type of the first action, if it exists, otherwise ''
        """
        return self._actions[0].action if self._actions else ''

    def _get_or_create_graph_node(self, type_: int, ins_addr: int, uid: int, *constructor_params) -> BaseDepNode:
        """
        If the node already exists in the graph, that node is returned. Otherwise, a new node is created
        :param _type: Type of node to check/create
        :param ins_addr: The address of the instruction that generated the associated action
        :param uid: The unique identifier of the SimAction
        :param constructor_params: Variadic list of arguments to supply for node lookup / creation
        :return: A reference to a node with the given parameters
        """

        if type_ is DepNodeTypes.Register:
            node = VarDepNode(type_, ins_addr, uid, *constructor_params)
        elif type_ is DepNodeTypes.Memory:
            node = MemDepNode(type_, ins_addr, uid, *constructor_params)
        elif type_ is DepNodeTypes.Integer:
            node = IntDepNode(type_, ins_addr, uid, *constructor_params)
        else:
            raise TypeError("Type must be a type of DepNode.")

        if node not in self._canonical_graph_nodes:
            self._graph.add_node(node, label=repr(node))
            self._canonical_graph_nodes[node] = node

        return self._canonical_graph_nodes[node]

    def _get_dep_node(self, dep_type: int, ins_addr: int, uid: int, var_src: Union[BV, int], val_src: Union[BV, int],
                      act: Optional[SimActionData] = None) -> Tuple[BaseDepNode, BaseDepNode]:
        if isinstance(var_src, BVV):
            var_src = self._end_state.solver.eval(var_src)
        if isinstance(val_src, BVV):
            val_src = self._end_state.solver.eval(val_src)

        var_num = self._end_state.solver.eval(var_src)
        var_node = self._get_or_create_graph_node(dep_type, ins_addr, uid, *[var_num])
        val_node = self._get_or_create_graph_node(DepNodeTypes.Integer, ins_addr, uid,
                                                  self._end_state.solver.eval(val_src))

        if act and dep_type is DepNodeTypes.Register and not var_node.arch_name:
            var_node.arch_name = act.storage

        return var_node, val_node

    def _get_reg_read_node(self, act: SimActionData) -> Tuple[BaseDepNode, BaseDepNode]:
        return self._get_dep_node(DepNodeTypes.Register, act.ins_addr, act.id,
                                  act.all_objects[0].ast, act.data.ast, act)

    def _get_reg_write_node(self, act: SimActionData) -> Tuple[BaseDepNode, BaseDepNode]:
        return self._get_dep_node(DepNodeTypes.Register, act.ins_addr,
                                  act.id, act.all_objects[0].ast, act.actual_value.ast, act)

    def _get_tmp_read_node(self, act: SimActionData) -> Tuple[BaseDepNode, BaseDepNode]:
        return self._get_dep_node(DepNodeTypes.Register, act.ins_addr, act.id, act.tmp, act.all_objects[1].ast, act)

    def _get_tmp_write_node(self, act: SimActionData) -> Tuple[BaseDepNode, BaseDepNode]:
        return self._get_dep_node(DepNodeTypes.Register, act.ins_addr, act.id, act.tmp, act.all_objects[1].ast, act)

    def _get_mem_read_node(self, act: SimActionData) -> Tuple[BaseDepNode, BaseDepNode]:
        return self._get_dep_node(DepNodeTypes.Memory, act.ins_addr, act.id, act.addr.ast, act.data.ast)

    def _get_mem_write_node(self, act: SimActionData) -> Tuple[BaseDepNode, BaseDepNode]:
        return self._get_dep_node(DepNodeTypes.Memory, act.ins_addr, act.id, act.addr.ast, act.data.ast)

    def _parse_read_from_var(self) -> Tuple[BaseDepNode, BaseDepNode]:
        """

        CFG
        read_from_var -> READ REG --> INT
        read_from_var -> READ MEM --> INT
        read_from_var -> read_from_var write_to_var
        """

        act_one = self._peek()
        act_two = self._peek(1)

        read_act = self._pop()
        var_type = read_act.type

        if var_type is SimActionData.REG:
            var_node, val_node = self._get_reg_read_node(read_act)
        elif var_type is SimActionData.TMP:
            var_node, val_node = self._get_tmp_read_node(read_act)
        elif var_type is SimActionData.MEM:
            var_node, val_node = self._get_mem_read_node(read_act)
        else:
            raise TypeError("Unable to parse read of %r with type %s", self._peek(), var_type)

        if act_two and act_one.ins_addr == act_two.ins_addr:

            # Rather than default, want to add edge between two tmp/mem/reg
            write_var, write_val = self._parse_write_to_var(False)

            if val_node is not write_val:
                _l.error("Same instruction address for read value %r and write value %r", val_node, write_val)
                _l.error("%r and %r\n\n", act_one, act_two)

            self._graph.add_edge(var_node, write_var)
            return write_var, var_node
        else:
            self._graph.add_edge(var_node, val_node)  # Value is dependent on variable being read
            return var_node, val_node

    def _parse_write_to_var(self, should_add_edge: bool = True) -> Tuple[BaseDepNode, BaseDepNode]:
        """

        CFG
        write_to_var -> WRITE TMP --> INT
        write_to_var -> WRITE REG --> INT
        write_to_var -> WRITE MEM --> INT
        """

        write_act = self._pop()
        var_type = write_act.type

        if var_type is SimActionData.REG:
            var_node, val_node = self._get_reg_write_node(write_act)
        elif var_type is SimActionData.TMP:
            var_node, val_node = self._get_tmp_write_node(write_act)
        elif var_type is SimActionData.MEM:
            var_node, val_node = self._get_mem_write_node(write_act)
        else:
            raise TypeError("Unable to parse write of %r with type %s", self._peek(), var_type)

        if should_add_edge:
            self._graph.add_edge(val_node, var_node)  # Variable is dependent on value

        return var_node, val_node

    def _parse_action(self):
        """
        action -> write_to_var
        action -> read_from_var
        action -> write_to_var action
        action -> read_from_var action
        """
        if self._peek_action() is SimActionData.READ:
            self._parse_read_from_var()
        elif self._peek_action() is SimActionData.WRITE:
            self._parse_write_to_var()
        else:
            _l.error("Unable to parse %r with action %s", self._peek(), self._peek_action())

    def _parse_statement(self):
        """
        statement -> write_var
        statement -> read_var statement
        :return:
        """
        action = self._peek()

        value_source_map: Dict[int, BaseDepNode] = {}

        if action.type is SimActionData.WRITE:
            # End of statement
            write_node = self._parse_write_to_var()

            if len(value_source_map.values()) == 1:
                # Only one source where write node could come from
                # TODO: Some information should be stored on the edge (direct store or math?)
                self._graph.add_edge(value_source_map.values()[0], write_node)
            elif src_node := value_source_map.get(write_node.value, None):
                self._graph.add_edge(src_node, write_node)
            else:
                raise AngrAnalysisError("Node <%r> written to without tracked value source!" % write_node)
        elif action.type is SimActionData.READ:
            read_node = self._parse_read_from_var()
            value_source_map[read_node.value] = read_node  # TODO: Could have two same values from different sources
        else:
            raise TypeError("Unexpected action type <%s> in statement parsing." % action.type)

    def _parse_instruction(self):
        """
        instruction -> statement
        instruction -> statement instruction
        :return:
        """
        ins_addr = self._peek().ins_addr
        ins_actions = []

        # Parse all the actions of the instruction
        while ins_addr == self._peek().ins_addr:
            ins_actions += self._parse_statement()

        for var_node, val_node in ins_actions:
            if isinstance(var_node, IntDepNode):
                pass



    def _parse_actions(self):
        """
        Utilizes the following grammar to populate a DiGraph with DepNodes.

        write_to_var -> WRITE TMP/REG/MEM <-- INT
        write_to_var -> <read_from_var> <write_to_var>  # this is (tmp/reg/mem <-- tmp/reg/mem)
        read_from_var -> read tmp/reg/mem --> INT
        """
        if self._actions:
            self._parse_action()
            self._parse_actions()

    def _work(self):
        """

        """
        self._graph = networkx.DiGraph()

        relevant_actions: List[SimActionObject] = self._end_state.history.filter_actions(
            block_addr=self._start_from
        )[::-1]
        # We only care about SimActionData for this analysis
        self._actions = list(filter(lambda a: isinstance(a, SimActionData), relevant_actions))

        ins_str = ''
        ins_addr = self._actions[0].ins_addr
        stmt_addr = self._actions[0].stmt_idx

        for act in self._actions:
            if act.ins_addr != ins_addr:
                ins_addr = act.ins_addr
                print(ins_str)
                ins_str = f'{hex(ins_addr)}: '
            if stmt_addr != act.stmt_idx:
                stmt_addr = act.stmt_idx
                ins_str += ' '

            ins_str += 'R' if act.action is SimActionData.READ else 'W'
        self._parse_actions()

        # Run transitive reduction
        print(self._graph)
        print(self._graph.edges)
        print("DAG: " + str(networkx.algorithms.dag.is_directed_acyclic_graph(self._graph)))
        # self._graph = networkx.algorithms.dag.transitive_reduction(self._graph)
        # print(self._graph)

        # Visualize the graph


# register this analysis
from angr.analyses import AnalysesHub

AnalysesHub.register_default('DataDep', DataDependencyGraphAnalysis)

"""
a = 70; write a <--- 70
b = a; read a ---> 70; write b <---- 70
return b; read b ---> 70; write rax <--- 70
"""
