from typing import Optional, Tuple, Union, List, DefaultDict, TYPE_CHECKING
from collections import defaultdict
import logging

import networkx

from ailment import Block, AILBlockWalkerBase
from ailment.statement import ConditionalJump
from ailment.expression import Expression, BinaryOp, Const, Load

from angr.utils.graph import GraphUtils
from ..utils import first_nonlabel_statement, remove_last_statement
from ..structuring.structurer_nodes import IncompleteSwitchCaseHeadStatement, SequenceNode, MultiNode
from .optimization_pass import OptimizationPass, OptimizationPassStage, MultipleBlocksException

if TYPE_CHECKING:
    from ailment.expression import UnaryOp, Convert

_l = logging.getLogger(name=__name__)


class Case:
    """
    Describes a case in a switch-case construct.
    """

    __slots__ = (
        "original_node",
        "node_type",
        "variable_hash",
        "expr",
        "value",
        "target",
        "next_addr",
    )

    def __init__(
        self, original_node, node_type: Optional[str], variable_hash, expr, value: Union[int, str], target, next_addr
    ):
        self.original_node = original_node
        self.node_type = node_type
        self.variable_hash = variable_hash
        self.expr = expr
        self.value = value
        self.target = target
        self.next_addr = next_addr

    def __repr__(self):
        if self.value == "default":
            return f"Case default@{self.target:#x}"
        return f"Case {repr(self.original_node)}@{self.target:#x}: {self.expr} == {self.value}"

    def __eq__(self, other):
        if not isinstance(other, Case):
            return False
        return (
            self.original_node == other.original_node
            and self.node_type == other.node_type
            and self.variable_hash == other.variable_hash
            and self.value == other.value
            and self.target == other.target
            and self.next_addr == other.next_addr
        )

    def __hash__(self):
        return hash(
            (Case, self.original_node, self.node_type, self.variable_hash, self.value, self.target, self.next_addr)
        )


class StableVarExprHasher(AILBlockWalkerBase):
    """
    Obtain a stable hash of an AIL expression with respect to all variables and all operations applied on variables.
    """

    def __init__(self, expr: Expression):
        super().__init__()
        self.expr = expr
        self._hash_lst = []

        self.walk_expression(expr)
        self.hash = hash(tuple(self._hash_lst))

    def _handle_expr(self, expr_idx: int, expr: Expression, stmt_idx: int, stmt, block: Optional[Block]):
        if hasattr(expr, "variable"):
            self._hash_lst.append(expr.variable)
        else:
            super()._handle_expr(expr_idx, expr, stmt_idx, stmt, block)

    def _handle_Load(self, expr_idx: int, expr: Load, stmt_idx: int, stmt, block: Optional[Block]):
        self._hash_lst.append("Load")
        super()._handle_expr(expr_idx, expr, stmt_idx, stmt, block)

    def _handle_BinaryOp(self, expr_idx: int, expr: BinaryOp, stmt_idx: int, stmt, block: Optional[Block]):
        self._hash_lst.append(expr.op)
        super()._handle_BinaryOp(expr_idx, expr, stmt_idx, stmt, block)

    def _handle_UnaryOp(self, expr_idx: int, expr: "UnaryOp", stmt_idx: int, stmt, block: Optional[Block]):
        self._hash_lst.append(expr.op)
        super()._handle_UnaryOp(expr_idx, expr, stmt_idx, stmt, block)

    def _handle_Const(self, expr_idx: int, expr: Const, stmt_idx: int, stmt, block: Optional[Block]):
        self._hash_lst.append((expr.value, expr.bits))

    def _handle_Convert(self, expr_idx: int, expr: "Convert", stmt_idx: int, stmt, block: Optional[Block]):
        self._hash_lst.append(expr.to_bits)
        super()._handle_Convert(expr_idx, expr, stmt_idx, stmt, block)


class LoweredSwitchSimplifier(OptimizationPass):
    """
    Recognize and simplify lowered switch-case constructs.
    """

    ARCHES = [
        "AMD64",
    ]
    PLATFORMS = ["linux", "windows"]
    STAGE = OptimizationPassStage.BEFORE_REGION_IDENTIFICATION
    NAME = "Convert lowered switch-cases (if-else) to switch-cases"
    DESCRIPTION = (
        "Convert lowered switch-cases (if-else) to switch-cases. Only works when the Phoenix structuring "
        "algorithm is in use."
    )
    STRUCTURING = ["phoenix"]

    def __init__(self, func, blocks_by_addr=None, blocks_by_addr_and_idx=None, graph=None, **kwargs):
        super().__init__(
            func, blocks_by_addr=blocks_by_addr, blocks_by_addr_and_idx=blocks_by_addr_and_idx, graph=graph, **kwargs
        )
        self.analyze()

    def _check(self):
        # TODO: More filtering
        return True, None

    def _analyze(self, cache=None):
        variablehash_to_cases = self._find_cascading_switch_variable_comparisons()

        if not variablehash_to_cases:
            return

        graph_copy = networkx.DiGraph(self._graph)
        self.out_graph = graph_copy
        node_to_heads = defaultdict(set)

        for _, caselists in variablehash_to_cases.items():
            for cases in caselists:
                original_nodes = [case.original_node for case in cases if case.value != "default"]
                original_head: Block = original_nodes[0]
                original_nodes = original_nodes[1:]

                case_addrs = {(case.original_node, case.value, case.target, case.next_addr) for case in cases}

                expr = cases[0].expr

                # create a fake switch-case head node
                switch_stmt = IncompleteSwitchCaseHeadStatement(
                    original_head.statements[-1].idx, expr, case_addrs, ins_addr=original_head.statements[-1].ins_addr
                )
                new_head = original_head.copy()
                # replace the last instruction of the head node with switch_node
                new_head.statements[-1] = switch_stmt
                # update the block
                self._update_block(original_head, new_head)

                # sanity check that no switch head points to either itself
                # or to any if-head that was merged into the new switch head; this
                # would result in a successor node no longer being present in the graph
                if any(onode not in graph_copy for onode in original_nodes):
                    self.out_graph = None
                    return

                # add edges between the head and case nodes
                for onode in original_nodes:
                    successors = list(graph_copy.successors(onode))
                    for succ in successors:
                        if succ not in original_nodes:
                            graph_copy.add_edge(new_head, succ)
                            node_to_heads[succ].add(new_head)
                    graph_copy.remove_node(onode)

        # find shared case nodes and make copies of them
        # note that this only solves cases where *one* node is shared between switch-cases. a more general solution
        # requires jump threading reverter.
        for succ_node, heads in node_to_heads.items():
            if len(heads) > 1:
                # each head gets a copy of the node!
                node_successors = list(graph_copy.successors(succ_node))
                next_id = 0 if succ_node.idx is None else succ_node.idx + 1
                graph_copy.remove_node(succ_node)
                for head in heads:
                    node_copy = succ_node.copy()
                    node_copy.idx = next_id
                    next_id += 1
                    graph_copy.add_edge(head, node_copy)
                    for succ in node_successors:
                        if succ is succ_node:
                            graph_copy.add_edge(node_copy, node_copy)
                        else:
                            graph_copy.add_edge(node_copy, succ)

    def _find_cascading_switch_variable_comparisons(self):
        sorted_nodes = GraphUtils.quasi_topological_sort_nodes(self._graph)
        variable_comparisons = {}
        for node in sorted_nodes:
            r = self._find_switch_variable_comparison_type_a(node)
            if r is not None:
                variable_comparisons[node] = ("a",) + r
                continue
            r = self._find_switch_variable_comparison_type_b(node)
            if r is not None:
                variable_comparisons[node] = ("b",) + r
                continue

        varhash_to_caselists: DefaultDict[int, List[List[Case]]] = defaultdict(list)

        for head in variable_comparisons:
            cases = []
            last_comp = None
            comp = head
            while True:
                comp_type, variable_hash, expr, value, target, next_addr = variable_comparisons[comp]
                if cases:
                    last_varhash = cases[-1].variable_hash
                else:
                    last_varhash = None
                if last_varhash is None or last_varhash == variable_hash:
                    if target == comp.addr:
                        # invalid
                        break
                    cases.append(Case(comp, comp_type, variable_hash, expr, value, target, next_addr))
                else:
                    # new variable!
                    if last_comp is not None:
                        cases.append(Case(last_comp, None, last_varhash, None, "default", comp.addr, None))
                    break

                if comp is not head:
                    # non-head node has at most one predecessor
                    if self._graph.in_degree[comp] > 1:
                        break

                successors = [succ for succ in self._graph.successors(comp) if succ is not comp]
                succ_addrs = {succ.addr for succ in successors}
                if target in succ_addrs:
                    next_comp_addr = next(iter(succ_addr for succ_addr in succ_addrs if succ_addr != target), None)
                    if next_comp_addr is None:
                        break
                    try:
                        next_comp = self._get_block(next_comp_addr)
                    except MultipleBlocksException:
                        # multiple blocks :/ it's possible that other optimization passes have duplicated the default
                        # node. check it.
                        next_comp_many = list(self._get_blocks(next_comp_addr))
                        if next_comp_many[0] not in variable_comparisons:
                            cases.append(Case(comp, None, variable_hash, expr, "default", next_comp_addr, None))
                        # otherwise we don't support it
                        break
                    assert next_comp is not None
                    if next_comp in variable_comparisons:
                        last_comp = comp
                        comp = next_comp
                        continue
                    cases.append(Case(comp, None, variable_hash, expr, "default", next_comp_addr, None))
                break

            if cases:
                v = cases[-1].variable_hash
                for idx, existing_cases in list(enumerate(varhash_to_caselists[v])):
                    if self.cases_issubset(existing_cases, cases):
                        varhash_to_caselists[v][idx] = cases
                        break
                    if self.cases_issubset(cases, existing_cases):
                        break
                else:
                    varhash_to_caselists[v].append(cases)

        for v, caselists in list(varhash_to_caselists.items()):
            for idx, cases in list(enumerate(caselists)):
                # filter: there should be at least two non-default cases
                if len([case for case in cases if case.value != "default"]) < 2:
                    caselists[idx] = None
                    continue

                # filter: no type-a node after the first case node
                if any(case for case in cases[1:] if case.value != "default" and case.node_type == "a"):
                    caselists[idx] = None
                    continue

                # filter: each case is only reachable from a case node
                all_case_nodes = {case.original_node for case in cases}
                skipped = False
                for case in cases:
                    target_nodes = [
                        succ for succ in self._graph.successors(case.original_node) if succ.addr == case.target
                    ]
                    if len(target_nodes) != 1:
                        caselists[idx] = None
                        skipped = True
                        break
                    target_node = target_nodes[0]
                    nonself_preds = {pred for pred in self._graph.predecessors(target_node) if pred.addr == case.target}
                    if not nonself_preds.issubset(all_case_nodes):
                        caselists[idx] = None
                        skipped = True
                        break

                if skipped:
                    continue

            varhash_to_caselists[v] = [cl for cl in caselists if cl is not None]

        return varhash_to_caselists

    @staticmethod
    def _find_switch_variable_comparison_type_a(
        node,
    ) -> Optional[Tuple[int, Expression, int, int, int]]:
        # the type a is the last statement is a var == constant comparison, but
        # there is more than one non-label statement in the block

        if isinstance(node, Block) and node.statements:
            stmt = node.statements[-1]
            if stmt is not None and stmt is not first_nonlabel_statement(node):
                if (
                    isinstance(stmt, ConditionalJump)
                    and isinstance(stmt.true_target, Const)
                    and isinstance(stmt.false_target, Const)
                ):
                    cond = stmt.condition
                    if isinstance(cond, BinaryOp):
                        if isinstance(cond.operands[1], Const):
                            variable_hash = StableVarExprHasher(cond.operands[0]).hash
                            value = cond.operands[1].value
                            if cond.op == "CmpEQ":
                                target = stmt.true_target.value
                                next_node_addr = stmt.false_target.value
                            elif cond.op == "CmpNE":
                                target = stmt.false_target.value
                                next_node_addr = stmt.true_target.value
                            else:
                                return None
                            return variable_hash, cond.operands[0], value, target, next_node_addr

        return None

    @staticmethod
    def _find_switch_variable_comparison_type_b(
        node,
    ) -> Optional[Tuple[int, Expression, int, int, int]]:
        # the type b is the last statement is a var == constant comparison, and
        # there is only one non-label statement

        if isinstance(node, Block):
            stmt = first_nonlabel_statement(node)
            if stmt is not None and stmt is node.statements[-1]:
                if (
                    isinstance(stmt, ConditionalJump)
                    and isinstance(stmt.true_target, Const)
                    and isinstance(stmt.false_target, Const)
                ):
                    cond = stmt.condition
                    if isinstance(cond, BinaryOp):
                        if isinstance(cond.operands[1], Const):
                            variable_hash = StableVarExprHasher(cond.operands[0]).hash
                            value = cond.operands[1].value
                            if cond.op == "CmpEQ":
                                target = stmt.true_target.value
                                next_node_addr = stmt.false_target.value
                            elif cond.op == "CmpNE":
                                target = stmt.false_target.value
                                next_node_addr = stmt.true_target.value
                            else:
                                return None
                            return variable_hash, cond.operands[0], value, target, next_node_addr

        return None

    @staticmethod
    def restore_graph(
        node, last_stmt: IncompleteSwitchCaseHeadStatement, graph: networkx.DiGraph, full_graph: networkx.DiGraph
    ):
        last_node = node
        ca_default = [
            (onode, value, target, a) for onode, value, target, a in last_stmt.case_addrs if value == "default"
        ]
        ca_others = [
            (onode, value, target, a) for onode, value, target, a in last_stmt.case_addrs if value != "default"
        ]

        # non-default nodes
        ca_others = {ca[0].addr: ca for ca in ca_others}
        # extract the AIL block from last_node
        last_block = last_node
        if isinstance(last_block, SequenceNode):
            last_block = last_block.nodes[-1]
        if isinstance(last_block, MultiNode):
            last_block = last_block.nodes[-1]
        assert isinstance(last_block, Block)
        next_node_addr = last_block.addr

        while next_node_addr is not None and next_node_addr in ca_others:
            onode, value, target, next_node_addr = ca_others[next_node_addr]
            onode: Block

            if first_nonlabel_statement(onode) is not onode.statements[-1]:
                onode = onode.copy(statements=[onode.statements[-1]])

            graph.add_edge(last_node, onode)
            full_graph.add_edge(last_node, onode)

            target_node = next(iter(nn for nn in full_graph if nn.addr == target))
            graph.add_edge(onode, target_node)
            full_graph.add_edge(onode, target_node)

            if graph.has_edge(node, target_node):
                graph.remove_edge(node, target_node)
            if full_graph.has_edge(node, target_node):
                full_graph.remove_edge(node, target_node)

            # update last_node
            last_node = onode

        # default nodes
        if ca_default:
            onode, value, target, _ = ca_default[0]
            default_target = next(iter(nn for nn in full_graph if nn.addr == target))
            graph.add_edge(last_node, default_target)
            full_graph.add_edge(last_node, default_target)

            if graph.has_edge(node, default_target):
                graph.remove_edge(node, default_target)
            if full_graph.has_edge(node, default_target):
                full_graph.remove_edge(node, default_target)

        # all good - remove the last statement in node
        remove_last_statement(node)

    @staticmethod
    def cases_issubset(cases_0: List[Case], cases_1: List[Case]) -> bool:
        """
        Test if cases_0 is a subset of cases_1.
        """

        if len(cases_0) > len(cases_1):
            return False
        for case in cases_0:
            if case not in cases_1:
                return False
        return True
