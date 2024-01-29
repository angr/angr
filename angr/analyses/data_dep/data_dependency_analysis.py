"""Defines analysis that will generate a dynamic data-dependency graph"""

import logging
import math
from typing import Optional, List, Union, Dict, Set, Tuple, TYPE_CHECKING

from networkx import DiGraph

import claripy
from claripy.ast.bv import BV
from .dep_nodes import DepNodeTypes, ConstantDepNode, MemDepNode, VarDepNode, RegDepNode, TmpDepNode
from .sim_act_location import SimActLocation, DEFAULT_LOCATION, ParsedInstruction
from .. import Analysis
from ...analyses import AnalysesHub
from ...errors import AngrDDGError, AngrAnalysisError, SimValueError
from ...state_plugins import SimActionData
from ...storage import DefaultMemory

if TYPE_CHECKING:
    from .dep_nodes import BaseDepNode
    from angr import SimState

logger = logging.getLogger(name=__name__)


class NodalAnnotation(claripy.Annotation):
    """
    Allows a node to be stored as an annotation to a BV in a DefaultMemory instance
    """

    def __init__(self, node: "BaseDepNode"):
        self.node = node

    @property
    def relocatable(self) -> bool:
        """Can not be relocated in a simplification"""
        return False

    @property
    def eliminatable(self):
        """Can not be eliminated in a simplification"""
        return False


class DataDependencyGraphAnalysis(Analysis):
    """
    This is a DYNAMIC data dependency graph that utilizes a given SimState to produce a DDG graph that is accurate to
    the path the program took during execution.

    This analysis utilizes the SimActionData objects present in the provided SimState's action history to generate the
    dependency graph.
    """

    def __init__(
        self,
        end_state: "SimState",
        start_from: Optional[int] = None,
        end_at: Optional[int] = None,
        block_addrs: Optional[List[int]] = None,
    ):
        """
        :param end_state: Simulation state used to extract all SimActionData
        :param start_from: An address or None, Specifies where to start generation of DDG
        :param end_at: An address or None, Specifies where to end generation of DDG
        :param iterable or None block_addrs: List of block addresses that the DDG analysis should be run on
        """
        self._graph: Optional[DiGraph] = None
        self._simplified_graph: Optional[DiGraph] = None
        self._sub_graph: Optional[DiGraph] = None

        self._end_state = end_state
        self._start_from = start_from if start_from else self.project.entry
        self._end_at = end_at
        self._block_addrs = frozenset(block_addrs) if block_addrs else frozenset()

        self._register_file = DefaultMemory(memory_id="reg")  # Tracks the current state of all parsed registers
        self._register_file.set_state(self._end_state)
        self._memory_map = DefaultMemory(memory_id="mem")  # Tracks the current state of all parsed memory addresses
        self._memory_map.set_state(self._end_state)
        self._tmp_nodes: Dict[str, TmpDepNode] = {}  # Per-block: Maps temp name to its current node
        self._constant_nodes: Dict[int, ConstantDepNode] = {}  # Per program: Maps values to their ConstantDepNodes
        self._actions: List["SimActionData"] = []

        # Used by parser to track instruction addresses processed
        self._parsed_ins_addrs: List[ParsedInstruction] = []  # Instruction address, min stmt_idx, max stmt_idx

        # Parameter sanity check
        if self._block_addrs and self._end_at:
            raise AngrDDGError("Can not specify BOTH start/end addresses and a block list!")

        self._work()

    @property
    def graph(self) -> Optional[DiGraph]:
        return self._graph

    @property
    def simplified_graph(self) -> Optional[DiGraph]:
        return self._simplified_graph

    @property
    def sub_graph(self) -> Optional[DiGraph]:
        return self._sub_graph

    def _pop(self) -> Optional["SimActionData"]:
        """
        Safely pops the first action, if it exists.
        """
        return self._actions.pop(0) if self._actions else None

    def _peek(self, idx: int = 0) -> Optional["SimActionData"]:
        """
        Safely returns the first action, if it exists, without removing it

        :param idx: Index to peek at, default 0
        """
        return self._actions[idx] if len(self._actions) > idx else None

    def _peek_type(self) -> str:
        """
        Safely returns the type of the first action, if it exists, otherwise ''
        """
        return self._actions[0].type if self._actions else ""

    def _peek_action(self) -> str:
        """
        Safely returns the type of the first action, if it exists, otherwise ''
        """
        return self._actions[0].action if self._actions else ""

    def _set_active_node(self, node: "BaseDepNode"):
        arch_bw = self._end_state.arch.bits
        if isinstance(node, RegDepNode):
            annotated_bv = node.ast.annotate(NodalAnnotation(node))
            annotated_bv = annotated_bv.zero_extend(arch_bw - annotated_bv.size())
            self._register_file.store(node.reg, annotated_bv)
        elif isinstance(node, MemDepNode):
            annotated_bv = node.ast.annotate(NodalAnnotation(node))
            self._memory_map.store(node.addr, annotated_bv)
        elif isinstance(node, TmpDepNode):
            self._tmp_nodes[node.arch_name] = node
        elif isinstance(node, ConstantDepNode):
            self._constant_nodes[node.value] = node
        else:
            raise TypeError(f"{str(node)} is node a DepNode")

    def _get_active_node(self, node: "BaseDepNode") -> Optional["BaseDepNode"]:
        """
        Retrieves the currently active node from the provided node type's storage data structure
        :param node: Node to retrieve the ancestor of
        :return: The ancestor, if it exists
        """
        ret_node = None
        if isinstance(node, RegDepNode):
            reg_data = self._register_file.load(node.reg, self._end_state.arch.byte_width)
            if not reg_data.symbolic and len(reg_data.annotations) > 0:
                ret_node = reg_data.annotations[0].node
        elif isinstance(node, MemDepNode):
            mem_data = self._memory_map.load(node.addr, node.width)
            if not mem_data.symbolic and len(mem_data.annotations) > 0:
                ret_node = mem_data.annotations[0].node
        elif isinstance(node, TmpDepNode):
            ret_node = self._tmp_nodes.get(node.arch_name, None)
        elif isinstance(node, ConstantDepNode):
            ret_node = self._constant_nodes.get(node.value, None)
        else:
            raise TypeError(f"{str(node)} is node a DepNode")
        return ret_node

    def _get_or_create_graph_node(
        self,
        type_: int,
        sim_act: "SimActionData",
        val: Tuple["BV", int],
        *constructor_params,
    ) -> "BaseDepNode":
        """
        If the node already exists in the graph, that node is returned. Otherwise, a new node is created
        :param _type: Type of node to check/create
        :param sim_act: The SimActionData associated with the node
        :param val: The value to be assigned to the node, represented as a Tuple containing its BV and evaluation
        :param constructor_params: Variadic list of arguments to supply for node lookup / creation
        :return: A reference to a node with the given parameters
        """

        # Always create a new write node

        if type_ is DepNodeTypes.Register or type_ is DepNodeTypes.Tmp:
            # Create and configure new node
            node_cls = RegDepNode if type_ is DepNodeTypes.Register else TmpDepNode
            ret_node = node_cls(sim_act, *constructor_params)
            ret_node.ast = val[0]
            ret_node.value = val[1]
            if not ret_node.arch_name:
                ret_node.arch_name = sim_act.storage

            self._graph.add_node(ret_node)

        elif type_ is DepNodeTypes.Memory:
            ret_node = MemDepNode(sim_act, *constructor_params)
            ret_node.ast = val[0]
            ret_node.value = val[1]
            self._graph.add_node(ret_node)
        elif type_ is DepNodeTypes.Constant:
            val_int = val[1]
            if val_int not in self._constant_nodes:
                self._constant_nodes[val_int] = ConstantDepNode(sim_act, val_int)
                self._graph.add_node(self._constant_nodes[val_int])
            ret_node = self._constant_nodes[val_int]
        else:
            raise TypeError("Type must be a type of DepNode.")

        return ret_node

    def _get_dep_node(
        self, dep_type: int, sim_act: SimActionData, var_src: Union[int, "BV"], val: Union[int, BV]
    ) -> "BaseDepNode":
        if isinstance(var_src, BV):
            var_src = self._end_state.solver.eval(var_src)

        val_ast = val
        if isinstance(val, BV):
            val = self._end_state.solver.eval(val)

        var_node = self._get_or_create_graph_node(dep_type, sim_act, (val_ast, val), *[var_src])

        return var_node

    def _get_generic_node(self, action: SimActionData) -> "BaseDepNode":
        def node_attributes(act: SimActionData) -> tuple:
            ac = act.action
            ty = act.type

            if ty not in [SimActionData.REG, SimActionData.TMP, SimActionData.MEM]:
                raise AngrAnalysisError(f"Unsupported type: <{ty}>!")
            if ac not in [SimActionData.WRITE, SimActionData.READ]:
                raise AngrAnalysisError(f"Unsupported action type: <{ac}>!")

            if ty == SimActionData.REG:
                if ac == SimActionData.READ:
                    tup = DepNodeTypes.Register, act.all_objects[0].ast, act.data.ast
                else:
                    tup = DepNodeTypes.Register, act.all_objects[0].ast, act.actual_value.ast
            elif ty == SimActionData.TMP:
                tup = DepNodeTypes.Tmp, act.tmp, act.all_objects[1].ast
            else:
                # Must be of type MEM, as we have already done a check
                tup = DepNodeTypes.Memory, act.addr.ast, act.data.ast
            return tup

        dep_type, var_src, val = node_attributes(action)
        return self._get_dep_node(dep_type, action, var_src, val)

    def _node_value_cmp(self, n1: "BaseDepNode", n2: "BaseDepNode") -> bool:
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
        try:
            return self._end_state.solver.eval_one(n1_cmp_ast == n2_cmp_ast)
        except SimValueError as s_val_err:
            logger.error(s_val_err)
            return False

    def _parse_action(self) -> "BaseDepNode":
        return self._get_generic_node(self._pop())

    def _parse_read_statement(self, read_nodes: Optional[Dict[int, List["BaseDepNode"]]] = None) -> "BaseDepNode":
        act = self._peek()
        read_node = self._parse_action()
        ancestor_node = self._get_active_node(read_node)

        if ancestor_node:
            # An ancestor exists for this read, and must be linked
            self._graph.add_edge(ancestor_node, read_node, label="ancestor")

        # Determine if read node should be marked a dependency of a constant value
        has_ancestor_and_new_value = ancestor_node is not None and not self._node_value_cmp(ancestor_node, read_node)
        is_orphan_and_new_value = ancestor_node is None and not self._constant_nodes.get(read_node.value)

        if has_ancestor_and_new_value or is_orphan_and_new_value:
            # This is a value that isn't inherited from a previous statement
            val_node = self._get_or_create_graph_node(DepNodeTypes.Constant, act, read_node.value_tuple(), True)
            self._graph.add_edge(val_node, read_node)

        read_nodes.setdefault(read_node.value, [])
        read_nodes[read_node.value].append(read_node)

        return read_node

    def _create_dep_edges(self, act, write_node, read_nodes: Dict[int, List["BaseDepNode"]]) -> bool:
        """Last resort for linking dependencies"""
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
            if dep_node and isinstance(dep_node, TmpDepNode):
                dep_found = True
                self._graph.add_edge(dep_node, write_node, label="unknown_dep")

        for reg_off in act.reg_deps:
            dep_node = possible_dep_nodes.get(reg_off, None)
            if dep_node and not isinstance(dep_node, TmpDepNode):
                dep_found = True
                self._graph.add_edge(dep_node, write_node, label="unknown_dep")

        return dep_found

    def _parse_var_statement(self, read_nodes: Optional[Dict[int, List["BaseDepNode"]]] = None) -> SimActLocation:
        act = self._peek()
        act_loc = SimActLocation(act.bbl_addr, act.ins_addr, act.stmt_idx)

        if act.action == SimActionData.WRITE:
            write_node = self._parse_action()

            src_nodes = read_nodes.get(write_node.value, None)
            if src_nodes:
                # Write value came from a previous read value
                for src_node in src_nodes:
                    self._graph.add_edge(src_node, write_node, label="val")
                read_nodes.pop(write_node.value, None)  # Remove from read nodes before backup edge finder

                # Helps with edge cases, ensures no more dependencies remain as tracked in tmp_deps and reg_deps
                # per the SAO
                self._create_dep_edges(act, write_node, read_nodes)
            elif len(read_nodes) == 0:
                # No reads in this instruction before first write, so its value is direct
                # if ConstantDepNode(write_node.value) not in self._canonical_graph_nodes:
                val_node = self._get_or_create_graph_node(DepNodeTypes.Constant, act, write_node.value_tuple(), True)
                self._graph.add_edge(val_node, write_node)
            elif len(read_nodes) == 1:
                # Some calculation must have been performed on the value of the single read
                stmt_read_nodes = list(read_nodes.values())[0]

                for stmt_read_node in stmt_read_nodes:
                    # diff = list(read_nodes.keys())[0] - write_node.value
                    # edge_label = f"{'-' if diff > 0 else '+'} {abs(diff)}"
                    self._graph.add_edge(stmt_read_node, write_node)  # label=edge_label)
            else:
                dep_found = self._create_dep_edges(act, write_node, read_nodes)
                if not dep_found:
                    logger.warning("Node <%r> written to without tracked value source!", write_node)

            self._set_active_node(write_node)
            return act_loc
        else:
            read_node = self._parse_read_statement(read_nodes=read_nodes)
            self._set_active_node(read_node)

            # Sometimes an R is the last action in a statement
            return (
                self._parse_statement(read_nodes) if self._peek() and act.stmt_idx == self._peek().stmt_idx else act_loc
            )

    def _parse_mem_statement(self, read_nodes: Optional[Dict[int, List["BaseDepNode"]]] = None) -> SimActLocation:
        act = self._peek()
        act_loc = SimActLocation(act.bbl_addr, act.ins_addr, act.stmt_idx)

        if act.action == SimActionData.WRITE:
            mem_node = MemDepNode.cast_to_mem(self._parse_action())
            src_nodes = read_nodes.get(mem_node.value, None)
            if src_nodes:
                # Value being written to, address came from previous read
                for src_node in src_nodes:
                    self._graph.add_edge(src_node, mem_node, label="val")
            elif len(read_nodes) == 1 and read_nodes.get(mem_node.addr, None):
                # Only read thus far was for the memory address, value is direct
                val_node = self._get_or_create_graph_node(DepNodeTypes.Constant, act, mem_node.value_tuple(), True)
                self._graph.add_edge(val_node, mem_node)
            else:
                raise AngrAnalysisError(f"Unexpected MemWrite pattern encountered! <{act}>")
            self._set_active_node(mem_node)
            ret_val = act_loc
        else:
            mem_node = self._parse_read_statement(read_nodes)
            self._set_active_node(mem_node)
            # Sometimes an R is the last action in a statement
            ret_val = None if self._peek() and act.stmt_idx == self._peek().stmt_idx else act_loc

        # Handle the address of the mem R/W
        addr_source_nodes = read_nodes.get(mem_node.addr, None)
        if addr_source_nodes:
            for addr_source_node in addr_source_nodes:
                self._graph.add_edge(addr_source_node, mem_node, label="addr_source")

        return ret_val if ret_val else self._parse_statement(read_nodes)

    def _parse_statement(self, read_nodes: Optional[Dict[int, List["BaseDepNode"]]] = None) -> SimActLocation:
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
        if (
            sim_act.action == SimActionData.WRITE
            and nxt_act
            and nxt_act.ins_addr == sim_act.ins_addr
            and nxt_act.stmt_idx == sim_act.stmt_idx
        ):
            raise AngrAnalysisError(
                "Statement must end with a write," f"but {self._peek(1)} follows a write!", self._peek(1)
            )

        if sim_act.type == SimActionData.MEM:
            return self._parse_mem_statement(read_nodes)
        else:
            return self._parse_var_statement(read_nodes)  # Tmp or Reg

    def _parse_instruction(self) -> SimActLocation:
        """
        Grammar:
        instruction -> statement
        instruction -> statement instruction

        :returns: The instruction address and last statement index of the parsed instruction
        """

        while True:
            loc = self._parse_statement()

            if not self._actions or loc.ins_addr != self._peek().ins_addr:
                # End of instruction
                return loc

    def _parse_block(self):
        """
        block -> instruction
        block -> instruction block
        """

        while True:
            start_stmt_idx = self._peek().stmt_idx  # Statement index of first statement in instruction

            end_loc = self._parse_instruction()

            # Add most recently parsed instruction to instructions data structure
            parsed_ins = ParsedInstruction(end_loc.ins_addr, start_stmt_idx, end_loc.stmt_idx)
            self._parsed_ins_addrs.insert(0, parsed_ins)

            if not self._actions or end_loc.bbl_addr != self._peek().bbl_addr:
                # Block continues with at least one more instruction
                break

    def _parse_blocks(self):
        """
        blocks -> block
        blocks -> block blocks
        """
        if self._actions:
            self._tmp_nodes.clear()  # Nodes are unique to a block
            self._parse_block()
            self._parse_blocks()

    def _filter_sim_actions(self) -> List[SimActionData]:
        """
        Using the user's start/end address OR block address list parameters,
        filters the actions down to those that are relevant
        :return: The relevant actions
        """

        if self._block_addrs:
            # Retrieve all actions from the given block(s)
            relevant_actions = list(
                filter(lambda act: act.bbl_addr in self._block_addrs, list(self._end_state.history.actions.hardcopy))
            )
        elif self._end_at:
            relevant_actions = self._end_state.history.filter_actions(
                start_block_addr=self._start_from, end_block_addr=self._end_at
            )[::-1]
        else:
            relevant_actions = self._end_state.history.filter_actions(start_block_addr=self._start_from)[::-1]

        # We only care about SimActionData objects for this analysis
        relevant_actions = list(
            filter(lambda act: isinstance(act, SimActionData) and act.sim_procedure is None, relevant_actions)
        )
        return relevant_actions

    def _work(self):
        """
        Generates the DDG
        """
        self._graph = DiGraph()
        self._actions = self._filter_sim_actions()

        # ins_str = curr_node
        # ins_addr = self._actions[0].ins_addr
        # stmt_addr = self._actions[0].stmt_idx
        #
        # for act in self._actions:
        #     if act.ins_addr != ins_addr:
        #         ins_addr = act.ins_addr
        #         print(ins_str)
        #         ins_str = f'{hex(ins_addr)}: '
        #     if stmt_addr != act.stmt_idx:
        #         stmt_addr = act.stmt_idx
        #         ins_str += ' '
        #
        #     ins_str += 'R' if act.action is SimActionData.READ else 'W'
        self._parse_blocks()

        # Create a simplified version of the graph
        self._simplified_graph = self._simplify_graph(self._graph)

    @staticmethod
    def _simplify_graph(G: DiGraph) -> DiGraph:
        """
        Performs an in-place removal of all tmp nodes and reconnects var nodes and mem nodes.
        :param G: Graph to be simplified
        """

        g0 = G.copy()
        tmp_nodes = [n for n in g0.nodes() if isinstance(n, TmpDepNode)]
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
    def _get_related_nodes(G: DiGraph, curr_node: "BaseDepNode", nodes: Set["BaseDepNode"], get_ancestors: bool):
        nodes.add(curr_node)

        next_nodes = G.predecessors(curr_node) if get_ancestors else G.successors(curr_node)

        if next_nodes:
            for p in next_nodes:
                if not isinstance(p, RegDepNode) or p.arch_name not in ["rsp", "rbp"]:
                    # Tracking RSP/RBP as sources just clutters the graph...
                    DataDependencyGraphAnalysis._get_related_nodes(G, p, nodes, get_ancestors)
        else:
            return

    def get_data_dep(self, g_node: "BaseDepNode", include_tmp_nodes: bool, backwards: bool) -> Optional[DiGraph]:
        # We have a matching node and can proceed to build a subgraph
        if g_node in self._graph:
            relevant_nodes = set()
            g = self._graph if include_tmp_nodes else self._simplified_graph

            DataDependencyGraphAnalysis._get_related_nodes(g, g_node, relevant_nodes, backwards)
            self._sub_graph = g.subgraph(relevant_nodes).copy()
            return self._sub_graph
        else:
            logger.error("No node %r in existing graph.", g_node)
            return None


# register this analysis
AnalysesHub.register_default("DataDep", DataDependencyGraphAnalysis)
