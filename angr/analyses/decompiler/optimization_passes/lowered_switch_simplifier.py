from typing import Optional, Tuple, Union, List, DefaultDict, TYPE_CHECKING
from collections import defaultdict, OrderedDict
import logging

import networkx

from ailment import Block, AILBlockWalkerBase
from ailment.statement import ConditionalJump, Label, Assignment, Jump
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
        "target_idx",
        "next_addr",
    )

    def __init__(
        self,
        original_node,
        node_type: Optional[str],
        variable_hash,
        expr,
        value: Union[int, str],
        target,
        target_idx: Optional[int],
        next_addr,
    ):
        self.original_node = original_node
        self.node_type = node_type
        self.variable_hash = variable_hash
        self.expr = expr
        self.value = value
        self.target = target
        self.target_idx = target_idx
        self.next_addr = next_addr

    def __repr__(self):
        if self.value == "default":
            return f"Case default@{self.target:#x}{'' if self.target_idx is None else '.' + str(self.target_idx)}"
        return (
            f"Case {repr(self.original_node)}@{self.target:#x}"
            f"{'' if self.target_idx is None else '.' + str(self.target_idx)}: {self.expr} == {self.value}"
        )

    def __eq__(self, other):
        if not isinstance(other, Case):
            return False
        return (
            self.original_node == other.original_node
            and self.node_type == other.node_type
            and self.variable_hash == other.variable_hash
            and self.value == other.value
            and self.target == other.target
            and self.target_idx == other.target_idx
            and self.next_addr == other.next_addr
        )

    def __hash__(self):
        return hash(
            (
                Case,
                self.original_node,
                self.node_type,
                self.variable_hash,
                self.value,
                self.target,
                self.target_idx,
                self.next_addr,
            )
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
        if hasattr(expr, "variable") and expr.variable is not None:
            self._hash_lst.append(expr.variable)
        else:
            super()._handle_expr(expr_idx, expr, stmt_idx, stmt, block)

    def _handle_Load(self, expr_idx: int, expr: Load, stmt_idx: int, stmt, block: Optional[Block]):
        self._hash_lst.append("Load")
        super()._handle_Load(expr_idx, expr, stmt_idx, stmt, block)

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
    STAGE = OptimizationPassStage.DURING_REGION_IDENTIFICATION
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
            for cases, redundant_nodes in caselists:
                original_nodes = [case.original_node for case in cases if case.value != "default"]
                original_head: Block = original_nodes[0]
                original_nodes = original_nodes[1:]
                existing_nodes_by_addr_and_idx = {(nn.addr, nn.idx): nn for nn in graph_copy}

                case_addrs: List[Tuple[Block, Union[int, str], int, Optional[int], int]] = []
                delayed_edges = []
                for idx, case in enumerate(cases):
                    if idx == 0 or all(
                        isinstance(stmt, (Label, ConditionalJump)) for stmt in case.original_node.statements
                    ):
                        case_addrs.append(
                            (case.original_node, case.value, case.target, case.target_idx, case.next_addr)
                        )
                    else:
                        statements: List = [
                            stmt for stmt in case.original_node.statements if isinstance(stmt, (Label, Assignment))
                        ]
                        statements.append(
                            Jump(
                                None,
                                Const(None, None, case.target, self.project.arch.bits),
                                ins_addr=case.original_node.addr,
                            )
                        )
                        case_node_copy = case.original_node.copy(statements=statements)
                        case_addrs.append(
                            (case_node_copy, case.value, case_node_copy.addr, case_node_copy.idx, case.next_addr)
                        )

                        # add this copied node into the graph
                        delayed_edges.append((None, case_node_copy))
                        target_node = existing_nodes_by_addr_and_idx[case.target, case.target_idx]
                        delayed_edges.append((case_node_copy, target_node))

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
                for onode in redundant_nodes:
                    # ensure all nodes that are only reachable from onode are also removed
                    # FIXME: Remove the entire path of nodes instead of only the immediate successors
                    successors = list(graph_copy.successors(onode))
                    graph_copy.remove_node(onode)
                    for succ in successors:
                        in_edges = [(src, dst) for src, dst in graph_copy.in_edges(succ) if src is not succ]
                        if not in_edges:
                            graph_copy.remove_node(succ)
                # apply delayed edges
                for src, dst in delayed_edges:
                    if src is None:
                        graph_copy.add_edge(new_head, dst)
                    else:
                        graph_copy.add_edge(src, dst)

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

                    # update the block ID in case_addrs
                    last_stmt: IncompleteSwitchCaseHeadStatement = head.statements[-1]
                    for idx, items in list(enumerate(last_stmt.case_addrs)):
                        cmp_node, case_value, target_addr, target_idx, next_addr = items
                        if target_addr == succ_node.addr and target_idx == succ_node.idx:
                            # update the block ID
                            last_stmt.case_addrs[idx] = cmp_node, case_value, target_addr, node_copy.idx, next_addr

                    # update the graph
                    graph_copy.add_edge(head, node_copy)
                    for succ in node_successors:
                        if succ is succ_node:
                            graph_copy.add_edge(node_copy, node_copy)
                        else:
                            graph_copy.add_edge(node_copy, succ)

    def _find_cascading_switch_variable_comparisons(self):
        sorted_nodes = GraphUtils.quasi_topological_sort_nodes(self._graph)
        variable_comparisons = OrderedDict()
        for node in sorted_nodes:
            r = self._find_switch_variable_comparison_type_a(node)
            if r is not None:
                variable_comparisons[node] = ("a",) + r
                continue
            r = self._find_switch_variable_comparison_type_b(node)
            if r is not None:
                variable_comparisons[node] = ("b",) + r
                continue
            r = self._find_switch_variable_comparison_type_c(node)
            if r is not None:
                variable_comparisons[node] = ("c",) + r
                continue

        varhash_to_caselists: DefaultDict[int, List[Tuple[List[Case], List]]] = defaultdict(list)
        used_nodes = set()

        for head in variable_comparisons:
            if head in used_nodes:
                continue

            cases = []
            extra_cmp_nodes = []
            default_case_candidates = {}
            last_comp = None
            stack = [(head, 0, 0xFFFF_FFFF_FFFF_FFFF)]
            while stack:
                comp, min_, max_ = stack.pop(0)
                (
                    comp_type,
                    variable_hash,
                    op,
                    expr,
                    value,
                    target,
                    target_idx,
                    next_addr,
                    next_addr_idx,
                ) = variable_comparisons[comp]
                if cases:
                    last_varhash = cases[-1].variable_hash
                else:
                    last_varhash = None

                if op == "eq":
                    # eq always indicates a new case

                    if last_varhash is None or last_varhash == variable_hash:
                        if target == comp.addr and target_idx == comp.idx:
                            # invalid
                            break
                        # common case:
                        #   if ((a = func(...)) == -1) break;
                        #   switch (a)
                        if value in {0xFFFF_FFFF, 0xFFFF_FFFF_FFFF_FFFF}:
                            break

                        if comp is not head:
                            # non-head node has at most one predecessor
                            if self._graph.in_degree[comp] > 1:
                                break

                        cases.append(Case(comp, comp_type, variable_hash, expr, value, target, target_idx, next_addr))
                        used_nodes.add(comp)
                    else:
                        # new variable!
                        if last_comp is not None:
                            if comp.addr not in default_case_candidates:
                                default_case_candidates[comp.addr] = Case(
                                    last_comp, None, last_varhash, None, "default", comp.addr, comp.idx, None
                                )
                        break

                    successors = [succ for succ in self._graph.successors(comp) if succ is not comp]
                    succ_addrs = {(succ.addr, succ.idx) for succ in successors}
                    if (target, target_idx) in succ_addrs:
                        next_comp_addr, next_comp_idx = next(
                            iter(
                                (succ_addr, succ_idx)
                                for succ_addr, succ_idx in succ_addrs
                                if (succ_addr, succ_idx) != (target, target_idx)
                            ),
                            (None, None),
                        )
                        if next_comp_addr is None:
                            break
                        try:
                            next_comp = self._get_block(next_comp_addr, idx=next_comp_idx)
                        except MultipleBlocksException:
                            # multiple blocks :/ it's possible that other optimization passes have duplicated the
                            # default node. check it.
                            next_comp_many = list(self._get_blocks(next_comp_addr))
                            next_comp_candidates = [succ for succ in successors if succ in next_comp_many]
                            if len(next_comp_candidates) == 1:
                                next_comp = next_comp_candidates[0]
                            else:
                                default_node_candidates = [
                                    succ for succ in next_comp_many if succ not in variable_comparisons
                                ]
                                if len(default_node_candidates) == 1:
                                    cases.append(
                                        Case(
                                            comp,
                                            None,
                                            variable_hash,
                                            expr,
                                            "default",
                                            next_comp_addr,
                                            next_comp_idx,
                                            None,
                                        )
                                    )
                                    used_nodes.add(comp)
                                # otherwise we don't support it
                                break
                        assert next_comp is not None
                        if next_comp in variable_comparisons:
                            last_comp = comp
                            stack.append((next_comp, min_, max_))
                            used_nodes.add(comp)
                        else:
                            if next_comp_addr not in default_case_candidates:
                                default_case_candidates[next_comp_addr] = Case(
                                    comp, None, variable_hash, expr, "default", next_comp_addr, next_comp_idx, None
                                )
                                used_nodes.add(comp)

                elif op == "gt":
                    # gt always indicates new subtrees
                    gt_addr, gt_idx, le_addr, le_idx = target, target_idx, next_addr, next_addr_idx
                    # TODO: We don't yet support gt nodes acting as the head of a switch
                    if last_varhash is not None and last_varhash == variable_hash:
                        successors = [succ for succ in self._graph.successors(comp) if succ is not comp]
                        succ_addrs = {(succ.addr, succ.idx) for succ in successors}
                        if succ_addrs != {(gt_addr, gt_idx), (le_addr, le_idx)}:
                            break
                        gt_comp = next(iter(succ for succ in successors if succ.addr == gt_addr and succ.idx == gt_idx))
                        le_comp = next(iter(succ for succ in successors if succ.addr == le_addr and succ.idx == le_idx))

                        # all successors of this node must satisfy the following criteria
                        # - another comp node in the lowered switch-case tree
                        # - the default case node of the switch-case

                        gt_added, le_added = False, False
                        if gt_comp in variable_comparisons:
                            stack.append((gt_comp, value, max_))
                            gt_added = True
                        if le_comp in variable_comparisons:
                            stack.append((le_comp, min_, value - 1))
                            le_added = True
                        if gt_added or le_added:
                            if not le_added:
                                if le_addr not in default_case_candidates:
                                    default_case_candidates[le_addr] = Case(
                                        comp, None, variable_hash, expr, "default", le_addr, le_idx, None
                                    )
                            elif not gt_added:
                                if gt_addr not in default_case_candidates:
                                    default_case_candidates[gt_addr] = Case(
                                        comp, None, variable_hash, expr, "default", gt_addr, gt_idx, None
                                    )
                            extra_cmp_nodes.append(comp)
                            used_nodes.add(comp)
                        else:
                            break
                    else:
                        # checking on a new variable... it probably was not a switch-case
                        break

            if cases and len(default_case_candidates) <= 1:
                if default_case_candidates:
                    cases.append(next(iter(default_case_candidates.values())))
                v = cases[-1].variable_hash
                for idx, (existing_cases, existing_redundant_nodes) in list(enumerate(varhash_to_caselists[v])):
                    if self.cases_issubset(existing_cases, cases):
                        redundant_nodes = list(set(existing_redundant_nodes + extra_cmp_nodes))
                        varhash_to_caselists[v][idx] = cases, redundant_nodes
                        break
                    if self.cases_issubset(cases, existing_cases):
                        break
                else:
                    varhash_to_caselists[v].append((cases, extra_cmp_nodes))

        for v, caselists in list(varhash_to_caselists.items()):
            for idx, (cases, redundant_nodes) in list(enumerate(caselists)):
                # filter: each case value should only appear once
                if len({case.value for case in cases}) != len(cases):
                    caselists[idx] = None
                    continue

                # filter: there should be at least two non-default cases
                if len([case for case in cases if case.value != "default"]) < 2:
                    caselists[idx] = None
                    continue

                # filter: there should be at least three cases
                if len(cases) < 3:
                    caselists[idx] = None
                    continue

                # filter: type-a nodes after the first case node can only have assignments
                for case in cases[1:]:
                    if case.value != "default" and case.node_type == "a":
                        for stmt in case.original_node.statements:
                            if not isinstance(stmt, (ConditionalJump, Label, Assignment)):
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

            varhash_to_caselists[v] = [item for item in caselists if item is not None]

        return varhash_to_caselists

    @staticmethod
    def _find_switch_variable_comparison_type_a(
        node,
    ) -> Optional[Tuple[int, str, Expression, int, int, Optional[int], int, Optional[int]]]:
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
                                target_idx = stmt.true_target_idx
                                next_node_addr = stmt.false_target.value
                                next_node_idx = stmt.false_target_idx
                            elif cond.op == "CmpNE":
                                target = stmt.false_target.value
                                target_idx = stmt.false_target_idx
                                next_node_addr = stmt.true_target.value
                                next_node_idx = stmt.true_target_idx
                            else:
                                return None
                            return (
                                variable_hash,
                                "eq",
                                cond.operands[0],
                                value,
                                target,
                                target_idx,
                                next_node_addr,
                                next_node_idx,
                            )

        return None

    @staticmethod
    def _find_switch_variable_comparison_type_b(
        node,
    ) -> Optional[Tuple[int, str, Expression, int, int, Optional[int], int, Optional[int]]]:
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
                                target_idx = stmt.true_target_idx
                                next_node_addr = stmt.false_target.value
                                next_node_idx = stmt.false_target_idx
                            elif cond.op == "CmpNE":
                                target = stmt.false_target.value
                                target_idx = stmt.false_target_idx
                                next_node_addr = stmt.true_target.value
                                next_node_idx = stmt.true_target_idx
                            else:
                                return None
                            return (
                                variable_hash,
                                "eq",
                                cond.operands[0],
                                value,
                                target,
                                target_idx,
                                next_node_addr,
                                next_node_idx,
                            )

        return None

    @staticmethod
    def _find_switch_variable_comparison_type_c(
        node,
    ) -> Optional[Tuple[int, str, Expression, int, int, Optional[int], int, Optional[int]]]:
        # the type c is where the last statement is a var < or > constant comparison, and
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
                            op = cond.op
                            if stmt.true_target.value == stmt.false_target.value:
                                return None
                            if op == "CmpGT":
                                op_str = "gt"
                                gt_node_addr = stmt.true_target.value
                                gt_node_idx = stmt.true_target_idx
                                le_node_addr = stmt.false_target.value
                                le_node_idx = stmt.false_target_idx
                            elif op == "CmpGE":
                                op_str = "gt"
                                value += 1
                                gt_node_addr = stmt.true_target.value
                                gt_node_idx = stmt.true_target_idx
                                le_node_addr = stmt.false_target.value
                                le_node_idx = stmt.false_target_idx
                            elif op == "CmpLT":
                                op_str = "gt"
                                value -= 1
                                gt_node_addr = stmt.false_target.value
                                gt_node_idx = stmt.false_target_idx
                                le_node_addr = stmt.true_target.value
                                le_node_idx = stmt.true_target_idx
                            elif op == "CmpLE":
                                op_str = "gt"
                                gt_node_addr = stmt.false_target.value
                                gt_node_idx = stmt.false_target_idx
                                le_node_addr = stmt.true_target.value
                                le_node_idx = stmt.true_target_idx
                            else:
                                return None
                            return (
                                variable_hash,
                                op_str,
                                cond.operands[0],
                                value,
                                gt_node_addr,
                                gt_node_idx,
                                le_node_addr,
                                le_node_idx,
                            )

        return None

    @staticmethod
    def restore_graph(
        node, last_stmt: IncompleteSwitchCaseHeadStatement, graph: networkx.DiGraph, full_graph: networkx.DiGraph
    ):
        last_node = node
        ca_default = [
            (onode, value, target, target_idx, a)
            for onode, value, target, target_idx, a in last_stmt.case_addrs
            if value == "default"
        ]
        ca_others = [
            (onode, value, target, target_idx, a)
            for onode, value, target, target_idx, a in last_stmt.case_addrs
            if value != "default"
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
            onode, value, target, target_idx, next_node_addr = ca_others[next_node_addr]
            onode: Block

            if first_nonlabel_statement(onode) is not onode.statements[-1]:
                onode = onode.copy(statements=[onode.statements[-1]])

            graph.add_edge(last_node, onode)
            full_graph.add_edge(last_node, onode)

            target_node = next(
                iter(
                    nn
                    for nn in full_graph
                    if nn.addr == target and (not isinstance(nn, (Block, MultiNode)) or nn.idx == target_idx)
                )
            )
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
            onode, value, target, target_idx, _ = ca_default[0]
            default_target = next(
                iter(
                    nn
                    for nn in full_graph
                    if nn.addr == target and (not isinstance(nn, (Block, MultiNode)) or nn.idx == target_idx)
                )
            )
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
