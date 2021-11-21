from __future__ import annotations  # Makes all type hints strings that aren't evaluated (helps with cyclical imports)

import itertools
import logging
from copy import copy
from typing import TYPE_CHECKING, Set

import networkx

from claripy.ast.bv import BV
from . import Analysis
from ..state_plugins import SimActionData, SimActionObject

from ..errors import AngrAnalysisError

if TYPE_CHECKING:
    from typing import Optional, TYPE_CHECKING, List, Union, Dict
    from .. import SimState

_l = logging.getLogger(name=__name__)


class DepNodeTypes:
    Memory = 1
    Register = 2
    Constant = 3
    Unknown = 4


class BaseDepNode:
    """
    Base class for all nodes in a data-dependency graph
    """

    def __init__(self, type_: int, instruction_addr: int, stmt_idx: int):
        self._type = type_
        self._instruction_addr = instruction_addr
        self._stmt_idx = stmt_idx
        self._value: Optional[int] = None

    @property
    def value(self):
        return self._value

    @value.setter
    def value(self, new_val: int):
        self._value = new_val

    @property
    def ins_addr(self) -> int:
        return self._instruction_addr

    @ins_addr.setter
    def ins_addr(self, new_ins_addr: int):
        self._instruction_addr = new_ins_addr

    @property
    def stmt_idx(self) -> int:
        """
        Statement index of action
        :return:
        """
        return self._stmt_idx

    @stmt_idx.setter
    def stmt_idx(self, new_stmt_idx: int):
        self._stmt_idx = new_stmt_idx

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
        return self.type == other.type and self.ins_addr == other.ins_addr

    def __hash__(self):
        return hash(self.type) ^ hash(self.ins_addr)


class ConstantDepNode(BaseDepNode):
    def __init__(self, value: int):
        super(ConstantDepNode, self).__init__(DepNodeTypes.Constant, 0, 0)  # Don't care about where constant came from
        self.value = value

    def __repr__(self):
        return f"Constant{hex(self.value)}"

    def __eq__(self, other):
        return self.value == other.value

    def __hash__(self):
        return hash(self.value)


class VarDepNode(BaseDepNode):
    def __init__(self, ins_addr: int, stmt_idx: int, reg: int, arch_name: str = ''):
        super(VarDepNode, self).__init__(DepNodeTypes.Register, ins_addr, stmt_idx)
        self.reg = reg
        self.arch_name = arch_name

    def __repr__(self):
        inner = self.arch_name if self.arch_name else hex(self.reg)
        val_str = 'None' if self.value is None else hex(self.value)
        return f"{inner}@{hex(self.ins_addr)}:{self.stmt_idx}\n{val_str}"

    def __eq__(self, other):
        return super(VarDepNode, self).__eq__(other) and self.reg == other.reg

    def __hash__(self):
        return super(VarDepNode, self).__hash__() ^ hash(self.reg)


class VarDepWriteNode(VarDepNode):
    def __init__(self, ins_addr: int, stmt_idx: int, reg: int, arch_name: str = ''):
        super(VarDepWriteNode, self).__init__(ins_addr, stmt_idx, reg, arch_name)

    def __eq__(self, other):
        return super(VarDepWriteNode, self).__eq__(other) and self.stmt_idx == other.stmt_idx

    def __hash__(self):
        return super(VarDepWriteNode, self).__hash__() ^ hash(self.stmt_idx)


class VarDepReadNode(VarDepNode):
    def __init__(self, ins_addr: int, stmt_idx: int, reg: int, arch_name: str = ''):
        super(VarDepReadNode, self).__init__(ins_addr, stmt_idx, reg, arch_name)


class MemDepNode(BaseDepNode):
    def __init__(self, ins_addr: int, stmt_idx: int, addr: int):
        super(MemDepNode, self).__init__(DepNodeTypes.Memory, ins_addr, stmt_idx)
        self.addr = addr

    def __repr__(self):
        val_str = 'None' if self.value is None else hex(self.value)
        return f"{hex(self.addr)}\n{hex(self.ins_addr)}:{self.stmt_idx}\n{val_str}"

    def __eq__(self, other):
        return super(MemDepNode, self).__eq__(other) and self.addr == other.addr

    def __hash__(self):
        return super(MemDepNode, self).__hash__() ^ hash(self.addr)


class MemDepWriteNode(MemDepNode):
    def __init__(self, ins_addr: int, stmt_idx: int, addr: int):
        super(MemDepWriteNode, self).__init__(ins_addr, stmt_idx, addr)

    def __eq__(self, other):
        return super(MemDepWriteNode, self).__eq__(other) and self.stmt_idx == other.stmt_idx

    def __hash__(self):
        return super(MemDepWriteNode, self).__hash__() ^ hash(self.stmt_idx)


class MemDepReadNode(MemDepNode):
    def __init__(self, ins_addr: int, stmt_idx: int, addr: int):
        super(MemDepReadNode, self).__init__(ins_addr, stmt_idx, addr)


def _is_tmp_node(node: BaseDepNode) -> bool:
    """
    :param node: Node to test
    :return: Returns whether or not the given node is a temp node.
    """
    return isinstance(node, VarDepNode) and node.arch_name.startswith('tmp')


class DataDependencyGraphAnalysis(Analysis):
    """
    generates a proximity graph based off data-dependency.
    """

    def __init__(self, end_state: SimState, start_from=None, end_at=None):
        """

        :param end_state: Simulation state used to extract all SimActionData from
        :param start_from: An address, Specifies where to start generation of DDG
        """
        self._graph: Optional[networkx.DiGraph] = None
        self._simplified_graph: Optional[networkx.DiGraph] = None
        self._end_state = end_state
        self._start_from = start_from if start_from else self.project.entry
        self._end_at = end_at
        self._canonical_graph_nodes: Dict[
            BaseDepNode, BaseDepNode] = dict()  # Maps a node to itself for lookup purposes

        self._actions: List[SimActionData] = []
        self._parsed_ins_addrs: List[int] = []  # Used by parser to track instruction addresses processed
        self._work()

    @property
    def graph(self) -> Optional[networkx.DiGraph]:
        return self._graph

    @property
    def simplified_graph(self) -> Optional[networkx.DiGraph]:
        return self._simplified_graph

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

    def _get_or_create_graph_node(self, type_: int, sim_act: SimActionData,
                                  val: int, should_create: bool = True, *constructor_params) -> BaseDepNode:
        """
        If the node already exists in the graph, that node is returned. Otherwise, a new node is created
        :param _type: Type of node to check/create
        :param sim_act: The SimActionData associated with the node
        :param val: The value to be assigned to the node
        :param should_create: If true, will add to canonical nodes if new. Otherwise, will just create lookup node
        :param constructor_params: Variadic list of arguments to supply for node lookup / creation
        :return: A reference to a node with the given parameters
        """

        action = sim_act.action
        ins_addr = sim_act.ins_addr
        stmt_idx = sim_act.stmt_idx

        if type_ is DepNodeTypes.Register:
            lookup_node = VarDepNode(ins_addr, stmt_idx, *constructor_params)
            lookup_node.value = val
            if not lookup_node.arch_name:
                lookup_node.arch_name = sim_act.storage
            store_node = copy(lookup_node)
            store_node.__class__ = VarDepReadNode if action is SimActionData.READ else VarDepWriteNode
        elif type_ is DepNodeTypes.Memory:
            lookup_node = MemDepNode(ins_addr, stmt_idx, *constructor_params)
            lookup_node.value = val
            store_node = copy(lookup_node)
            store_node.__class__ = MemDepReadNode if action is SimActionData.READ else MemDepWriteNode
        elif type_ is DepNodeTypes.Constant:
            lookup_node = ConstantDepNode(val)
            store_node = copy(lookup_node)
        else:
            raise TypeError("Type must be a type of DepNode.")

        if not should_create:
            return lookup_node

        if lookup_node not in self._canonical_graph_nodes:
            # New node, write nodes should always get in here
            self._graph.add_node(store_node, label=repr(store_node))
            self._canonical_graph_nodes[lookup_node] = store_node

        return self._canonical_graph_nodes[lookup_node] if action is SimActionData.READ else store_node

    def _get_dep_node(self, dep_type: int, sim_act: SimActionData, var_src: Union[BV, int],
                      val: Union[BV, int], should_create: bool) -> BaseDepNode:
        if isinstance(var_src, BV):
            var_src = self._end_state.solver.eval(var_src)
        if isinstance(val, BV):
            val = self._end_state.solver.eval(val)

        var_node = self._get_or_create_graph_node(dep_type, sim_act, val, should_create, *[var_src])

        return var_node

    def _get_generic_node(self, action: SimActionData, should_create: bool = True) -> BaseDepNode:

        def node_attributes(act: SimActionData) -> tuple:
            ac = act.action
            ty = act.type

            if ac is SimActionData.READ:
                if ty is SimActionData.REG:
                    tup = DepNodeTypes.Register, act.all_objects[0].ast, act.data.ast,
                elif ty is SimActionData.TMP:
                    tup = DepNodeTypes.Register, act.tmp, act.all_objects[1].ast,
                elif ty is SimActionData.MEM:
                    tup = DepNodeTypes.Memory, act.addr.ast, act.data.ast,
                else:
                    raise AngrAnalysisError('Unsupported Read type: <%s>!', ty)
            elif ac is SimActionData.WRITE:
                if ty is SimActionData.REG:
                    tup = DepNodeTypes.Register, act.all_objects[0].ast, act.actual_value.ast,
                elif ty is SimActionData.TMP:
                    tup = DepNodeTypes.Register, act.tmp, act.all_objects[1].ast,
                elif ty is SimActionData.MEM:
                    tup = DepNodeTypes.Memory, act.addr.ast, act.data.ast,
                else:
                    raise AngrAnalysisError('Unsupported Write type: <%s>!', ty)
            else:
                raise AngrAnalysisError('Unsupported action type: <%s>!', ac)

            return tup

        dep_type, var_src, val = node_attributes(action)
        return self._get_dep_node(dep_type, action, var_src, val, should_create)

    def _parse_action(self) -> BaseDepNode:
        return self._get_generic_node(self._pop())

    def _get_most_recent_ancestor(self, curr_node: BaseDepNode, go_by_stmt: bool = False) -> Optional[BaseDepNode]:
        """
        Retrieves the most recent ancestor of the given node, if it exists
        :param curr_node: Node to search for an ancestor of
        :param go_by_stmt: Whether an ancestor from the same instruction is acceptable
        :return: The most recent ancestor, else None
        """
        ancestor_lookup_node = copy(curr_node)
        ancestor_node = None

        if go_by_stmt:
            if isinstance(ancestor_lookup_node, VarDepWriteNode):
                ancestor_lookup_node.__class__ = VarDepNode
            elif isinstance(ancestor_lookup_node, MemDepWriteNode):
                ancestor_lookup_node.__class__ = MemDepNode

            ins_addrs = list(self._parsed_ins_addrs)
            ins_addrs.insert(0, ancestor_lookup_node.ins_addr)

            for ins_addr, stmt_idx in itertools.product(ins_addrs, range(ancestor_lookup_node.stmt_idx - 1, 1, -1)):
                ancestor_lookup_node.ins_addr = ins_addr
                ancestor_lookup_node.stmt_idx = stmt_idx

                if found_node := self._canonical_graph_nodes.get(ancestor_lookup_node, None):
                    if curr_node != found_node:
                        # Cannot be the same node
                        ancestor_node = found_node
                        break
        else:
            for ins_addr in self._parsed_ins_addrs:
                ancestor_lookup_node.ins_addr = ins_addr
                if found_node := self._canonical_graph_nodes.get(ancestor_lookup_node, None):
                    ancestor_node = found_node
                    break

        return ancestor_node

    def _link_with_most_recent_ins_ancestor(self, curr_node: BaseDepNode):
        """
        Adds an edge between the given node and its most recent instruction ancestor, if it exists
        :param curr_node: Node to find an ancestor of
        """
        if ancestor_node := self._get_most_recent_ancestor(curr_node):
            self._graph.add_edge(ancestor_node, curr_node, label='ancestor')

    def _parse_read_statement(self, read_nodes: Optional[Dict[int, BaseDepNode]] = None) -> BaseDepNode:
        act = self._peek()
        pre_existing_node = self._canonical_graph_nodes.get(
            self._get_generic_node(act, should_create=False),
            None
        )

        read_node = self._parse_action()

        read_ancestor = self._get_most_recent_ancestor(read_node, go_by_stmt=True)

        # Determine if read node should be marked a dependency of a constant value
        has_ancestor_and_new_value = read_ancestor is not None and read_ancestor.value != read_node.value
        is_orphan_and_new_value = read_ancestor is None and pre_existing_node is None and ConstantDepNode(
            read_node.value) not in self._canonical_graph_nodes
        exists_with_new_value = pre_existing_node and pre_existing_node.value != read_node.value

        if has_ancestor_and_new_value or is_orphan_and_new_value or exists_with_new_value:
            # This is a value that isn't inherited from a previous statement
            val_node = self._get_or_create_graph_node(DepNodeTypes.Constant, act, read_node.value)
            self._graph.add_edge(val_node, read_node)

        self._link_with_most_recent_ins_ancestor(read_node)
        read_nodes[read_node.value] = read_node
        return read_node

    def _parse_var_statement(self, read_nodes: Optional[Dict[int, BaseDepNode]] = None) -> int:
        act = self._peek()

        if act.action is SimActionData.WRITE:
            write_node = self._parse_action()

            if src_node := read_nodes.get(write_node.value, None):
                # Write value came from a previous read value
                self._graph.add_edge(src_node, write_node, label='val')
            elif len(read_nodes) == 0:
                # No reads in this instruction before first write, so its value is direct
                if ConstantDepNode(write_node.value) not in self._canonical_graph_nodes:
                    val_node = self._get_or_create_graph_node(DepNodeTypes.Constant, act, write_node.value)
                    self._graph.add_edge(val_node, write_node)
            elif len(read_nodes) == 1:
                # Some calculation must have been performed on the value of the single read
                stmt_read_node = list(read_nodes.values())[0]
                diff = list(read_nodes.keys())[0] - write_node.value
                edge_label = f"{'-' if diff > 0 else '+'} {abs(diff)}"
                self._graph.add_edge(stmt_read_node, write_node, label=edge_label)
            else:
                _l.error("Node <%r> written to without tracked value source!" % write_node)

            return act.ins_addr
        else:
            self._parse_read_statement(read_nodes)
            return self._parse_statement(read_nodes)

    def _parse_mem_statement(self, read_nodes: Optional[Dict[int, BaseDepNode]] = None):
        act = self._peek()

        if act.action is SimActionData.WRITE:
            mem_node = self._parse_action()

            if src_node := read_nodes.get(mem_node.value, None):
                # Value being written to address came from previous read
                self._graph.add_edge(src_node, mem_node, label='val')
            elif len(read_nodes) == 1 and read_nodes.get(mem_node.addr, None):
                # Only read thus far was for the memory address, value is direct
                if ConstantDepNode(mem_node.value) not in self._canonical_graph_nodes:
                    val_node = self._get_or_create_graph_node(DepNodeTypes.Constant, act, mem_node.value)
                    self._graph.add_edge(val_node, mem_node)
                else:
                    _l.error("Already encountered %d written to <%r> without stmt read!", mem_node.value, mem_node)
            else:
                raise AngrAnalysisError("Unexpected MemWrite pattern encountered! <%r>", act)
            ret_val = act.ins_addr
        else:
            mem_node = self._parse_read_statement(read_nodes)
            ret_val = None

        # Handle the address of the mem R/W
        if addr_source_node := read_nodes.get(mem_node.addr, None):
            self._graph.add_edge(addr_source_node, mem_node, label='addr_source')

        return ret_val if ret_val else self._parse_statement(read_nodes)

    def _parse_statement(self, read_nodes: Optional[Dict[int, BaseDepNode]] = None) -> int:
        """
        statement -> write_var | write_mem
        statement -> read_var | write_mem statement
        :return: The instruction address associated with the statement
        """
        read_nodes = read_nodes if read_nodes else {}
        sim_act = self._peek()
        if not sim_act:
            return -1

        # Some sanity checks
        if sim_act.action not in [SimActionData.WRITE, SimActionData.READ]:
            raise AngrAnalysisError("Statement with unsupported action encountered: <%s>", sim_act.action)
        if sim_act.type not in [SimActionData.TMP, SimActionData.MEM, SimActionData.REG]:
            raise AngrAnalysisError("Statement with unsupported type encountered: <%s>", sim_act.type)
        if sim_act.action is SimActionData.WRITE and self._peek(1) and self._peek(1).stmt_idx == sim_act.stmt_idx:
            raise AngrAnalysisError("Statement must end with a write, but %r follows a write!", self._peek(1))

        if sim_act.type is SimActionData.MEM:
            return self._parse_mem_statement(read_nodes)
        else:
            return self._parse_var_statement(read_nodes)  # TMP or REG

    def _parse_instruction(self, ins_addr: Optional[int] = None):
        """
        instruction -> statement
        instruction -> statement instruction
        :return:
        """

        if not self._actions:
            return

        if ins_addr and ins_addr != self._peek().ins_addr:
            # End of instruction
            self._parsed_ins_addrs.insert(0, ins_addr)
            return

        ins_addr = self._parse_statement()
        self._parse_instruction(ins_addr)

    def _parse_instructions(self):
        """
        Utilizes the following grammar to populate a DiGraph with DepNodes.

        instructions -> instruction
        instructions -> instruction instructions
        """
        if self._actions:
            self._parse_instruction()
            self._parse_instructions()

    def _work(self):
        """

        """
        self._graph = networkx.DiGraph()

        relevant_actions: List[SimActionObject] = self._end_state.history.filter_actions(
            start_block_addr=self._start_from, end_block_addr=self._end_at
        )[::-1]

        # We only care about SimActionData for this analysis
        self._actions = list(
            filter(lambda a: isinstance(a, SimActionData) and a.sim_procedure is None, relevant_actions))

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
        self._parse_instructions()

        # Create a simplified version of the graph
        self._simplified_graph = self._simplify_graph(self._graph)

    def get_reg_data_dep(self, ins_addr: int, stmt_idx: int,
                         reg: int, pred_max: Optional[int] = None,
                         include_tmp_nodes: bool = True) -> Optional[networkx.DiGraph]:
        eq_reg_node = VarDepNode(ins_addr, stmt_idx, reg)
        return self._get_data_dep(eq_reg_node, pred_max, include_tmp_nodes)

    def get_mem_data_dep(self, ins_addr: int, stmt_idx: int,
                         addr: int, pred_max: Optional[int] = None,
                         include_tmp_nodes: bool = True) -> Optional[networkx.DiGraph]:
        eq_mem_node = MemDepNode(ins_addr, stmt_idx, addr)
        return self._get_data_dep(eq_mem_node, pred_max, include_tmp_nodes)

    @staticmethod
    def _simplify_graph(G: networkx.DiGraph) -> networkx.DiGraph:
        """
        Performs an in-place removal of all tmp nodes and reconnects varnodes and memnodes.
        :param G: Graph to be simplified
        """

        g0 = G.copy()
        tmp_nodes = [n for n in g0.nodes() if _is_tmp_node(n)]
        for curr_node in tmp_nodes:
            # Node must be removed and predecessor(s) connected to successor(s)
            in_edges = list(g0.in_edges(curr_node, data=True))
            out_edges = list(g0.out_edges(curr_node, data=True))

            for pred, _, _ in in_edges:
                g0.remove_edge(pred, curr_node)
            for _, suc, _ in out_edges:
                g0.remove_edge(curr_node, suc)

            # Ancestor nodes should not be considered in simplification
            # in_edges = list(filter(lambda edge: 'label' not in edge[2] or edge[2]['label'] != 'ancestor', in_edges))

            for pred, _, data_in in in_edges:
                for _, suc, data_out in out_edges:
                    data = data_in.copy()
                    data.update(data_out)
                    g0.add_edge(pred, suc, **data)

            g0.remove_node(curr_node)

        return g0

    @staticmethod
    def _get_parent_nodes(G: networkx.DiGraph, curr_node: BaseDepNode, nodes: Set[BaseDepNode]):
        nodes.add(curr_node)

        if pred_nodes := G.predecessors(curr_node):
            for p in pred_nodes:
                DataDependencyGraphAnalysis._get_parent_nodes(G, p, nodes)
        else:
            return

    def _get_data_dep(self, eq_node: BaseDepNode, pred_max: Optional[int], include_tmp_nodes: bool) -> Optional[
        networkx.DiGraph]:
        # TODO: Implement pred_max
        if g_node := self._canonical_graph_nodes.get(eq_node, None):
            # We have a matching node and can proceed to build a subgraph
            relevant_nodes = set()
            g = self._graph if include_tmp_nodes else self._simplified_graph
            DataDependencyGraphAnalysis._get_parent_nodes(g, g_node, relevant_nodes)
            return g.subgraph(relevant_nodes).copy()
        else:
            _l.error("No node %r in existing graph.", eq_node)


# register this analysis
from angr.analyses import AnalysesHub

AnalysesHub.register_default('DataDep', DataDependencyGraphAnalysis)
