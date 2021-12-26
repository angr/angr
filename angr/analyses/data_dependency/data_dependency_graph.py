"""Defines analysis that will generate a dynamic data-dependency graph"""
import logging
import math
from copy import copy
from typing import Optional, List, Union, Dict, Set, Tuple, TYPE_CHECKING
from networkx import DiGraph
from claripy.ast.bv import BV
from .. import Analysis
from ...errors import AngrDDGError, AngrAnalysisError
from ...analyses import AnalysesHub
from ...state_plugins import SimActionData
from .sim_act_location import SimActLocation, DEFAULT_LOCATION
from .dep_nodes import DepNodeTypes, ConstantDepNode, VarDepNode, VarDepReadNode, VarDepWriteNode
from .dep_nodes import VarOffset, MemDepNode, MemDepReadNode, MemDepWriteNode

if TYPE_CHECKING:
    from .dep_nodes import BaseDepNode
    from angr import SimState

logger = logging.getLogger(name=__name__)


class DataDependencyGraphAnalysis(Analysis):
    """
    This is a DYNAMIC data dependency graph that utilizes a given SimState to produce a DDG graph that is accurate to
    the path the program took during execution.

    This analysis utilizes the SimActionData objects present in the provided SimState's action history to generate the
    dependency graph.
    """

    def __init__(self, end_state: 'SimState', start_from: Optional[int] = None, end_at: Optional[int] = None,
                 block_addrs: Optional[List[int]] = None):
        """
        :param end_state: Simulation state used to extract all SimActionData
        :param start_from: An address or None, Specifies where to start generation of DDG
        :param end_at: An address or None, Specifies where to end generation of DDG
        :param iterable or None block_addrs: List of block addresses that the DDG analysis should be run on
        """
        self._graph: Optional[DiGraph] = None
        self._simplified_graph: Optional[DiGraph] = None
        self._end_state = end_state
        self._start_from = start_from if start_from else self.project.entry
        self._end_at = end_at
        self._block_addrs = frozenset(block_addrs)
        self._canonical_graph_nodes: Dict[
            'BaseDepNode', 'BaseDepNode'] = {}  # Maps a node to itself for lookup purposes
        self._actions: List['SimActionData'] = []

        # Used by parser to track instruction addresses processed
        self._parsed_ins_addrs: List[Tuple[int, int, int]] = []  # Instruction address, min stmt_idx, max stmt_idx

        # Parameter sanity check
        if not bool(self._block_addrs) ^ bool(self._end_at):
            raise AngrDDGError('Can not specify BOTH start/end addresses and a block list!')

        self._work()

    @property
    def graph(self) -> Optional[DiGraph]:
        return self._graph

    @property
    def simplified_graph(self) -> Optional[DiGraph]:
        return self._simplified_graph

    def _pop(self) -> Optional['SimActionData']:
        """
        Safely pops the first action, if it exists.
        """
        return self._actions.pop(0) if self._actions else None

    def _peek(self, idx: int = 0) -> Optional['SimActionData']:
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

    def _get_or_create_graph_node(self, type_: int,
                                  sim_act: 'SimActionData',
                                  val: Tuple['BV', int],
                                  should_create: bool,
                                  *constructor_params,
                                  ) -> 'BaseDepNode':
        """
        If the node already exists in the graph, that node is returned. Otherwise, a new node is created
        :param _type: Type of node to check/create
        :param sim_act: The SimActionData associated with the node
        :param val: The value to be assigned to the node, represented as a Tuple containing its BV and evaluation
        :param should_create: If true, will add to canonical nodes if new. Otherwise, will just create lookup node
        :param constructor_params: Variadic list of arguments to supply for node lookup / creation
        :return: A reference to a node with the given parameters
        """

        action = sim_act.action
        loc = SimActLocation(sim_act.ins_addr, sim_act.stmt_idx)

        if type_ is DepNodeTypes.Register:
            lookup_node = VarDepNode(loc, *constructor_params)
            lookup_node.ast = val[0]
            lookup_node.value = val[1]
            if not lookup_node.arch_name:
                lookup_node.arch_name = sim_act.storage
            store_node = copy(lookup_node)
            store_node = VarDepReadNode.cast(store_node) if action is SimActionData.READ\
                else VarDepWriteNode.cast(store_node)
        elif type_ is DepNodeTypes.Memory:
            lookup_node = MemDepNode(loc, *constructor_params)
            lookup_node.ast = val[0]
            lookup_node.value = val[1]
            store_node = copy(lookup_node)
            store_node = MemDepReadNode.cast(store_node) if action is SimActionData.READ\
                else MemDepWriteNode.cast(store_node)
        elif type_ is DepNodeTypes.Constant:
            lookup_node = ConstantDepNode(val[1])
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

    def _get_dep_node(self, dep_type: int, sim_act: SimActionData, var_src: Union[int, 'VarOffset'],
                      val: Union[int, BV], should_create: bool) -> 'BaseDepNode':
        if isinstance(var_src, BV):
            var_src = self._end_state.solver.eval(var_src)
        if isinstance(var_src, VarOffset) and isinstance(var_src.reg, BV):
            var_src.reg = self._end_state.solver.eval(var_src.reg)

        val_ast = val
        if isinstance(val, BV):
            val = self._end_state.solver.eval(val)

        var_node = self._get_or_create_graph_node(dep_type, sim_act, (val_ast, val), should_create, *[var_src])

        return var_node

    def _get_generic_node(self, action: SimActionData, should_create: bool = True) -> 'BaseDepNode':

        def node_attributes(act: SimActionData) -> tuple:
            ac = act.action
            ty = act.type

            if ty not in [SimActionData.REG, SimActionData.TMP, SimActionData.MEM]:
                raise AngrAnalysisError(f'Unsupported type: <{ty}>!')
            if ac not in [SimActionData.WRITE, SimActionData.READ]:
                raise AngrAnalysisError(f'Unsupported action type: <{ac}>!')

            if ty is SimActionData.REG:
                if ac is SimActionData.READ:
                    tup = DepNodeTypes.Register, VarOffset(act.all_objects[0].ast, False), act.data.ast
                else:
                    tup = DepNodeTypes.Register, VarOffset(act.all_objects[0].ast, False), act.actual_value.ast
            elif ty is SimActionData.TMP:
                tup = DepNodeTypes.Register, VarOffset(act.tmp, True), act.all_objects[1].ast
            else:
                # Must be of type MEM, as we have already done a check
                tup = DepNodeTypes.Memory, act.addr.ast, act.data.ast
            return tup

        dep_type, var_src, val = node_attributes(action)
        return self._get_dep_node(dep_type, action, var_src, val, should_create)

    def _node_value_compare(self, n1: 'BaseDepNode', n2: 'BaseDepNode') -> bool:
        """
        Performs a BV based comparison on the values of the nodes
        :param n1: First node to compare
        :param n2: Second node to compare
        :return: Whether the values of the nodes, bit-width dependent, are equivalent
        """

        # Zero-extend both values to the nearest byte for comparison
        def zero_extend_to_next_byte(ast: BV) -> BV:
            goal_bw = 8 * (math.ceil(ast.size() / 8))
            return ast.zero_extend(goal_bw - ast.size())

        ext_n1 = zero_extend_to_next_byte(n1.ast)
        ext_n2 = zero_extend_to_next_byte(n2.ast)

        if ext_n1.size() % 8 != 0 or ext_n2.size() % 8 != 0:
            # Something went wrong in extension
            raise ValueError("Cannot compare BV that aren't of a bit-width that is a multiple of 8!")

        cmp_bw = min(ext_n1.size(), ext_n2.size())
        cmp_byte_width = cmp_bw // 8

        n1_idx = ext_n1.size() // 8 - cmp_byte_width
        n2_idx = ext_n2.size() // 8 - cmp_byte_width
        n1_cmp_ast = ext_n1.get_bytes(n1_idx, cmp_byte_width)
        n2_cmp_ast = ext_n2.get_bytes(n2_idx, cmp_byte_width)
        return self._end_state.solver.eval_one(n1_cmp_ast == n2_cmp_ast)

    def _parse_action(self) -> 'BaseDepNode':
        return self._get_generic_node(self._pop())

    def _get_most_recent_ancestor(self, curr_node: 'BaseDepNode', go_by_stmt: bool = False) -> Optional['BaseDepNode']:
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

            ins_addrs = list(self._parsed_ins_addrs)  # Create a local copy
            curr_start_stmt_idx = ins_addrs[0][2] + 1  # Next statement index after most recent last stmt_idx

            # Don't want to include current statement in lookup
            ins_addrs.insert(0, (ancestor_lookup_node.ins_addr, curr_start_stmt_idx, curr_node.stmt_idx - 1))

            for ins_addr, start_stmt_idx, last_stmt_idx in ins_addrs:
                ancestor_lookup_node.ins_addr = ins_addr
                for stmt_idx in range(last_stmt_idx, start_stmt_idx - 1, -1):
                    ancestor_lookup_node.stmt_idx = stmt_idx

                    if found_node := self._canonical_graph_nodes.get(ancestor_lookup_node, None):
                        if curr_node != found_node:
                            # Cannot be the same node
                            ancestor_node = found_node
                            break

                if ancestor_node:
                    break
        else:
            for ins_addr in [x[0] for x in self._parsed_ins_addrs]:
                ancestor_lookup_node.ins_addr = ins_addr
                if found_node := self._canonical_graph_nodes.get(ancestor_lookup_node, None):
                    ancestor_node = found_node
                    break

        return ancestor_node

    def _link_with_most_recent_ins_ancestor(self, curr_node: 'BaseDepNode'):
        """
        Adds an edge between the given node and its most recent instruction ancestor, if it exists
        :param curr_node: Node to find an ancestor of
        """
        if ancestor_node := self._get_most_recent_ancestor(curr_node):
            self._graph.add_edge(ancestor_node, curr_node, label='ancestor')

    def _parse_read_statement(self, read_nodes: Optional[Dict[int, List['BaseDepNode']]] = None) -> 'BaseDepNode':
        act = self._peek()
        pre_existing_node = self._canonical_graph_nodes.get(
            self._get_generic_node(act, should_create=False),
            None
        )

        read_node = self._parse_action()
        read_ancestor = self._get_most_recent_ancestor(read_node, go_by_stmt=True)

        # Determine if read node should be marked a dependency of a constant value
        has_ancestor_and_new_value = not pre_existing_node and read_ancestor \
            and not self._node_value_compare(read_ancestor, read_node)
        is_orphan_and_new_value = not read_ancestor and not pre_existing_node and ConstantDepNode(
            read_node.value) not in self._canonical_graph_nodes
        exists_with_new_value = pre_existing_node and not self._node_value_compare(pre_existing_node, read_node)

        if has_ancestor_and_new_value or is_orphan_and_new_value or exists_with_new_value:
            # This is a value that isn't inherited from a previous statement
            val_node = self._get_or_create_graph_node(DepNodeTypes.Constant, act, read_node.value_tuple(), True)
            self._graph.add_edge(val_node, read_node)

        self._link_with_most_recent_ins_ancestor(read_node)
        read_nodes.setdefault(read_node.value, [])
        read_nodes[read_node.value].append(read_node)

        return read_node

    def _parse_var_statement(self, read_nodes: Optional[Dict[int, List['BaseDepNode']]] = None) -> SimActLocation:
        act = self._peek()
        act_loc = SimActLocation(act.ins_addr, act.stmt_idx)

        if act.action is SimActionData.WRITE:
            write_node = self._parse_action()

            # Check if write node is part of a comparison
            if src_nodes := read_nodes.get(write_node.value, None):
                # Write value came from a previous read value
                for src_node in src_nodes:
                    self._graph.add_edge(src_node, write_node, label='val')
            elif len(read_nodes) == 0:
                # No reads in this instruction before first write, so its value is direct
                # if ConstantDepNode(write_node.value) not in self._canonical_graph_nodes:
                val_node = self._get_or_create_graph_node(DepNodeTypes.Constant, act, write_node.value_tuple(), True)
                self._graph.add_edge(val_node, write_node)
            elif len(read_nodes) == 1:
                # Some calculation must have been performed on the value of the single read
                stmt_read_nodes = list(read_nodes.values())[0]

                for stmt_read_node in stmt_read_nodes:
                    diff = list(read_nodes.keys())[0] - write_node.value
                    edge_label = f"{'-' if diff > 0 else '+'} {abs(diff)}"
                    self._graph.add_edge(stmt_read_node, write_node, label=edge_label)
            else:
                # Check tmp and reg deps
                var_read_nodes = []
                for nodes in read_nodes.values():
                    for node in nodes:
                        if isinstance(node, VarDepNode):
                            var_read_nodes.append(node)

                possible_dep_nodes = {node.reg: node for node in var_read_nodes}

                dep_found = False

                for tmp_off in act.tmp_deps:
                    dep_node = possible_dep_nodes.get(tmp_off, None)
                    if dep_node and dep_node.is_tmp:
                        dep_found = True
                        self._graph.add_edge(dep_node, write_node, label='unknown_dep')

                for reg_off in act.reg_deps:
                    dep_node = possible_dep_nodes.get(reg_off, None)
                    if dep_node and not dep_node.is_tmp:
                        dep_found = True
                        self._graph.add_edge(dep_node, write_node, label='unknown_dep')

                if not dep_found:
                    logger.error("Node <%r> written to without tracked value source!", write_node)

            return act_loc
        else:
            self._parse_read_statement(read_nodes)

            # Sometimes an R is the last action in a statement
            return self._parse_statement(read_nodes) \
                if self._peek() and act.stmt_idx == self._peek().stmt_idx \
                else act_loc

    def _parse_mem_statement(self, read_nodes: Optional[Dict[int, List['BaseDepNode']]] = None) -> SimActLocation:
        act = self._peek()
        act_loc = SimActLocation(act.ins_addr, act.stmt_idx)

        if act.action is SimActionData.WRITE:
            mem_node = MemDepNode.cast(self._parse_action())
            if src_nodes := read_nodes.get(mem_node.value, None):
                # Value being written to address came from previous read
                for src_node in src_nodes:
                    self._graph.add_edge(src_node, mem_node, label='val')
            elif len(read_nodes) == 1 and read_nodes.get(mem_node.addr, None):
                # Only read thus far was for the memory address, value is direct
                val_node = self._get_or_create_graph_node(DepNodeTypes.Constant, act, mem_node.value_tuple(), True)
                self._graph.add_edge(val_node, mem_node)
            else:
                raise AngrAnalysisError(f"Unexpected MemWrite pattern encountered! <{act}>")
            ret_val = act_loc
        else:
            mem_node = self._parse_read_statement(read_nodes)
            # Sometimes an R is the last action in a statement
            ret_val = None if self._peek() and act.stmt_idx == self._peek().stmt_idx else act_loc

        # Handle the address of the mem R/W
        if addr_source_nodes := read_nodes.get(mem_node.addr, None):
            for addr_source_node in addr_source_nodes:
                self._graph.add_edge(addr_source_node, mem_node, label='addr_source')

        return ret_val if ret_val else self._parse_statement(read_nodes)

    def _parse_statement(self, read_nodes: Optional[Dict[int, List['BaseDepNode']]] = None) -> SimActLocation:
        """
        statement -> write_var | write_mem
        statement -> read_var | write_mem statement
        :return: The instruction address associated with the statement
        """
        read_nodes = read_nodes if read_nodes else {}
        sim_act = self._peek()
        nxt_act = self._peek(1)
        if not sim_act:
            return DEFAULT_LOCATION

        # Some sanity checks
        if sim_act.action not in [SimActionData.WRITE, SimActionData.READ]:
            raise AngrAnalysisError(f"Statement with unsupported action encountered: <{sim_act.action}>")
        if sim_act.type not in [SimActionData.TMP, SimActionData.MEM, SimActionData.REG]:
            raise AngrAnalysisError(f"Statement with unsupported type encountered: <{sim_act.type}>")
        if sim_act.action is SimActionData.WRITE and nxt_act \
                and nxt_act.ins_addr == sim_act.ins_addr and nxt_act.stmt_idx == sim_act.stmt_idx:
            raise AngrAnalysisError("Statement must end with a write,"
                                    f"but {self._peek(1)} follows a write!", self._peek(1))

        if sim_act.type is SimActionData.MEM:
            return self._parse_mem_statement(read_nodes)
        else:
            # Check if action is concerned with a comparison operator or operand
            return self._parse_var_statement(read_nodes)  # TMP or REG

    def _parse_instruction(self) -> SimActLocation:
        """
        Grammar:
        instruction -> statement
        instruction -> statement instruction

        :returns: The instruction address and last statement index of the parsed instruction
        """

        # ins_addr = loc.ins_addr if loc else None
        loc = self._parse_statement()

        if not self._actions or loc.ins_addr != self._peek().ins_addr:
            # End of instruction
            return loc
        else:
            return self._parse_instruction()

    def _parse_instructions(self):
        """
        Utilizes the following grammar to populate a DiGraph with DepNodes.

        instructions -> instruction
        instructions -> instruction instructions

        :param start_stmt_idx: The starting statement index of the instruction currently being processed
        """
        if self._actions:
            start_stmt_idx = self._peek().stmt_idx
            end_loc = self._parse_instruction()
            self._parsed_ins_addrs.insert(0, (end_loc.ins_addr, start_stmt_idx, end_loc.stmt_idx))
            self._parse_instructions()

    def _filter_sim_actions(self) -> List[SimActionData]:
        """
        Using the user's start/end address OR block address list parameters,
        filters the actions down to those that are relevant
        :return: The relevant actions
        """

        if self._block_addrs:
            # Retrieve all actions from the given block(s)
            relevant_actions = list(filter(
                lambda act: act.bbl_addr in self._block_addrs,
                list(self._end_state.history.actions.hardcopy)))
        else:
            relevant_actions = self._end_state.history.filter_actions(
                start_block_addr=self._start_from, end_block_addr=self._end_at
            )[::-1]

        # We only care about SimActionData objects for this analysis
        relevant_actions = list(filter(
            lambda act: isinstance(act, SimActionData) and act.sim_procedure is None,
            relevant_actions))
        return relevant_actions

    def _work(self):
        """
        Generates the DDG
        """
        self._graph = DiGraph()
        self._actions = self._filter_sim_actions()

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

    def get_reg_data_dep(self, loc: SimActLocation,
                         offset: VarOffset, pred_max: Optional[int] = None,
                         include_tmp_nodes: bool = True) -> Optional[DiGraph]:
        eq_reg_node = VarDepNode(loc, offset)
        return self._get_data_dep(eq_reg_node, pred_max, include_tmp_nodes)

    def get_mem_data_dep(self, loc: SimActLocation,
                         addr: int, pred_max: Optional[int] = None,
                         include_tmp_nodes: bool = True) -> Optional[DiGraph]:
        eq_mem_node = MemDepNode(loc, addr)
        return self._get_data_dep(eq_mem_node, pred_max, include_tmp_nodes)

    @staticmethod
    def _simplify_graph(G: DiGraph) -> DiGraph:
        """
        Performs an in-place removal of all tmp nodes and reconnects var nodes and mem nodes.
        :param G: Graph to be simplified
        """

        g0 = G.copy()
        tmp_nodes = [n for n in g0.nodes() if n.is_tmp]
        for curr_node in tmp_nodes:
            # Node must be removed and predecessor(s) connected to successor(s)
            in_edges = list(g0.in_edges(curr_node, data=True))
            out_edges = list(g0.edges(curr_node, data=True))

            for pred, _, _ in in_edges:
                g0.remove_edge(pred, curr_node)
            for _, suc, _ in out_edges:
                g0.remove_edge(curr_node, suc)

            for pred, _, data_in in in_edges:
                for _, suc, data_out in out_edges:
                    data = data_in.copy()
                    data.update(data_out)
                    g0.add_edge(pred, suc, **data)

            g0.remove_node(curr_node)

        return g0

    @staticmethod
    def _get_parent_nodes(G: DiGraph, curr_node: 'BaseDepNode', nodes: Set['BaseDepNode']):
        nodes.add(curr_node)

        if pred_nodes := G.predecessors(curr_node):
            for p in pred_nodes:
                DataDependencyGraphAnalysis._get_parent_nodes(G, p, nodes)
        else:
            return

    def _get_data_dep(self, eq_node: 'BaseDepNode', pred_max: Optional[int],
                      include_tmp_nodes: bool) -> Optional[DiGraph]:
        # TODO: Implement pred_max
        if g_node := self._canonical_graph_nodes.get(eq_node, None):
            # We have a matching node and can proceed to build a subgraph
            relevant_nodes = set()
            g = self._graph if include_tmp_nodes else self._simplified_graph
            DataDependencyGraphAnalysis._get_parent_nodes(g, g_node, relevant_nodes)
            return g.subgraph(relevant_nodes).copy()
        else:
            logger.error("No node %r in existing graph.", eq_node)
            return None


# register this analysis
AnalysesHub.register_default('DataDep', DataDependencyGraphAnalysis)
