# pylint:disable=no-self-use,arguments-renamed
import enum
from typing import DefaultDict, Any, List, Union, Dict, Tuple, Set, Optional
from collections import OrderedDict, defaultdict

import ailment

from ..structuring.structurer_nodes import SwitchCaseNode, ConditionNode, SequenceNode, MultiNode
from ..sequence_walker import SequenceWalker


class CmpOp(enum.Enum):
    """
    All supported comparison operators.
    """

    LT = 0
    GT = 1
    EQ = 2
    NE = 3


class ConditionalRegion:
    """
    Describes a conditional region.
    """

    __slots__ = (
        "variable",
        "op",
        "value",
        "node",
        "parent",
    )

    def __init__(self, variable, op: CmpOp, value: int, node: Union[ConditionNode, ailment.Block], parent=None):
        self.variable = variable
        self.op = op
        self.value = value
        self.node = node
        self.parent = parent

    def __repr__(self):
        return f"<{self.variable} {self.op} {self.value} @ {self.node.addr:#x}, parent node {self.parent}>"


class SwitchCaseRegion:
    """
    Describes an already-recovered switch region.
    """

    __slots__ = (
        "variable",
        "node",
        "parent",
    )

    def __init__(self, variable, node: SwitchCaseNode, parent=None):
        self.variable = variable
        self.node = node
        self.parent = parent

    def __repr__(self):
        return f"<{self.variable} ({len(self.node.cases)} cases) @ {self.node.addr:#x}, parent node {self.parent}>"


class SwitchClusterFinder(SequenceWalker):
    """
    Find comparisons and switches in order to identify switch clusters.
    """

    def __init__(self, node):
        handlers = {
            SwitchCaseNode: self._handle_SwitchCase,
            ConditionNode: self._handle_Condition,
            ailment.Block: self._handle_Block,
        }
        super().__init__(handlers)

        self.var2condnodes: DefaultDict[Any, List[ConditionalRegion]] = defaultdict(list)
        self.var2switches: DefaultDict[Any, List[SwitchCaseRegion]] = defaultdict(list)

        self.walk(node)

    def _handle_Block(self, node: ailment.Block, parent=None, **kwargs):  # pylint:disable=unused-argument
        if node.statements and isinstance(node.statements[-1], ailment.Stmt.ConditionalJump):
            cond = node.statements[-1].condition
            self._process_condition(cond, node, parent)

    def _handle_Condition(self, node, parent=None, **kwargs):
        cond = node.condition
        self._process_condition(cond, node, parent)
        return super()._handle_Condition(node, parent=parent, **kwargs)

    def _handle_SwitchCase(self, node: SwitchCaseNode, parent=None, **kwargs):
        cond = node.switch_expr
        if hasattr(cond, "variable"):
            variable = cond.variable
            scr = SwitchCaseRegion(variable, node, parent)
            self.var2switches[variable].append(scr)
        return super()._handle_SwitchCase(node, parent=parent, **kwargs)

    def _process_condition(self, cond: ailment.Expr.Expression, node: Union[ConditionNode, ailment.Block], parent):
        negated = False
        if isinstance(cond, ailment.Expr.UnaryOp) and cond.op == "Not":
            negated = True
            cond = cond.operand
        if isinstance(cond, ailment.Expr.BinaryOp) and cond.op in {
            "CmpLE",
            "CmpLT",
            "CmpGE",
            "CmpGT",
            "CmpEQ",
            "CmpNE",
        }:
            v = None
            variable = None
            if isinstance(cond.operands[1], ailment.Expr.Const):
                v = cond.operands[1].value
            if isinstance(cond.operands[0], (ailment.Expr.Register, ailment.Expr.Load)):
                if hasattr(cond.operands[0], "variable"):
                    # there we go
                    variable = cond.operands[0].variable

            if v is not None and variable is not None:
                if negated:
                    real_op = ailment.Expr.BinaryOp.COMPARISON_NEGATION[cond.op]
                else:
                    real_op = cond.op
                # eliminate equal
                if real_op == "CmpLE":
                    real_op = CmpOp.LT
                    v += 1
                elif real_op == "CmpGE":
                    real_op = CmpOp.GT
                    v -= 1
                elif real_op == "CmpLT":
                    real_op = CmpOp.LT
                elif real_op == "CmpGT":
                    real_op = CmpOp.GT
                elif real_op == "CmpEQ":
                    real_op = CmpOp.EQ
                elif real_op == "CmpNE":
                    real_op = CmpOp.NE
                else:
                    raise TypeError(f"Unsupported real_op value {real_op}")

                cr = ConditionalRegion(variable, real_op, v, node, parent=parent)
                self.var2condnodes[variable].append(cr)


class SwitchClusterReplacer(SequenceWalker):
    """
    Replace an identified switch cluster with a newly created SwitchCase node.
    """

    def __init__(self, region, to_replace, replace_with):
        handlers = {
            ConditionNode: self._handle_Condition,
        }
        super().__init__(handlers)

        self.to_replace = to_replace
        self.replace_with = replace_with
        self.walk(region)

    def _handle_Condition(self, node, **kwargs):
        if node is self.to_replace:
            return self.replace_with
        return super()._handle_Condition(node, **kwargs)


def is_simple_jump_node(node, case_addrs, targets: Optional[Set[int]] = None) -> bool:
    if isinstance(node, (SequenceNode, MultiNode)):
        return all(is_simple_jump_node(nn, case_addrs) for nn in node.nodes)
    if isinstance(node, ailment.Block):
        for stmt in node.statements:
            if isinstance(stmt, ailment.Stmt.Label):
                pass
            elif (
                isinstance(stmt, ailment.Stmt.Jump)
                and isinstance(stmt.target, ailment.Expr.Const)
                and stmt.target.value in case_addrs
            ):
                if targets is not None:
                    targets.add(stmt.target.value)
            elif isinstance(stmt, ailment.Stmt.ConditionalJump):
                ok = False
                if (
                    stmt.true_target is None
                    or isinstance(stmt.true_target, ailment.Expr.Const)
                    and stmt.true_target.value in case_addrs
                ):
                    ok = True
                    if stmt.true_target is not None and targets is not None:
                        targets.add(stmt.true_target.value)
                if (
                    stmt.false_target is None
                    or isinstance(stmt.false_target, ailment.Expr.Const)
                    and stmt.false_target.value in case_addrs
                ):
                    ok = True
                    if stmt.false_target is not None and targets is not None:
                        targets.add(stmt.false_target.value)
                if not ok:
                    return False
            else:
                return False
        return True
    return False


def filter_cond_regions(cond_regions: List[ConditionalRegion], case_addrs: Set[int]) -> List[ConditionalRegion]:
    """
    Remove all conditional regions that cannot be merged into switch(es).
    """

    # TODO: the check is too strict!

    new_cond_regions = []
    for r in cond_regions:
        ok = True
        if isinstance(r.node, ConditionNode):
            true_node, false_node = r.node.true_node, r.node.false_node
            # it should only contain a jump into one of the cases
            ok = (true_node is None or is_simple_jump_node(true_node, case_addrs)) and (
                false_node is None or is_simple_jump_node(false_node, case_addrs)
            )
        elif isinstance(r.node, ailment.Block):
            if not is_simple_jump_node(r.node, case_addrs):
                ok = False
        else:
            raise TypeError(f"Unsupported r.node type {type(r.node)}")

        if ok:
            new_cond_regions.append(r)

    return new_cond_regions


def update_switch_case_list(
    cases: List[Tuple[Union[int, Tuple[int, ...]], SequenceNode]],
    old_case_id: Union[int, Tuple[int, ...]],
    new_case_id: int,
) -> None:
    """
    Update cases in-place. Make new_case_id directly jump to old_case_id.
    """

    for i, (case_ids, case_node) in list(enumerate(cases)):
        if isinstance(case_ids, int):
            match = old_case_id == case_ids
            new_key = (case_ids, new_case_id)
        elif isinstance(case_ids, tuple):
            match = old_case_id == case_ids or old_case_id in case_ids
            new_key = case_ids + (new_case_id,)
        else:
            raise TypeError(f"Unsupported case_ids type {type(case_ids)}")
        if match:
            cases[i] = (new_key, case_node)
            break


def simplify_switch_clusters(
    region, var2condnodes: Dict[Any, List[ConditionalRegion]], var2switches: Dict[Any, List[SwitchCaseRegion]]
):
    """
    Identify switch clusters and simplify each of them.

    :param region:          The region to simplify.
    :param var2condnodes:   A dict that stores the mapping from (potential) switch variables to conditional regions.
    :param var2switches:    A dict that stores the mapping from switch variables to switch-case regions.
    :return:                None
    """

    for variable in var2switches:
        switch_regions = var2switches[variable]
        cond_regions = list(var2condnodes[variable])

        if not cond_regions:
            continue

        # each switch region belongs to a conditional region
        switch_region_to_parent_region: Dict[SwitchCaseRegion, Tuple[ConditionalRegion, str]] = {}
        used_condnodes_and_branch = set()
        for r in switch_regions:
            for cr in cond_regions:
                if isinstance(cr.node, ConditionNode):
                    if cr.node.true_node is r.node:
                        switch_region_to_parent_region[r] = (cr, "true")
                        used_condnodes_and_branch.add((cr, "true"))
                        break
                    if cr.node.false_node is r.node:
                        switch_region_to_parent_region[r] = (cr, "false")
                        used_condnodes_and_branch.add((cr, "false"))
                        break
        if len(switch_region_to_parent_region) != len(switch_regions):
            continue

        # there is at most one default node
        default_node_addrs = {r.node.default_node.addr for r in switch_regions if r.node.default_node is not None}
        if len(default_node_addrs) > 1:
            continue

        # ensure cases in each switch do not overlap
        case_ids = set()
        overlaps = False
        for r in switch_regions:
            for case_id in r.node.cases:
                if case_id in case_ids:
                    overlaps = True
                    break
                case_ids.add(case_id)
            if overlaps:
                break
        if overlaps:
            continue

        used_condnodes = list(condnode for condnode, _ in used_condnodes_and_branch)

        # collect addresses for all case nodes
        case_addr_to_case_id: Dict[int, Union[int, Tuple[int, ...], str]] = {}
        for sr in switch_regions:
            for case_id, case_node in sr.node.cases.items():
                case_addr_to_case_id[case_node.addr] = case_id
            if sr.node.default_node is not None:
                case_addr_to_case_id[sr.node.default_node.addr] = "default"
        case_addrs: Set[int] = set(case_addr_to_case_id)

        # filter cond_regions
        mergeable_cond_regions = filter_cond_regions(cond_regions, case_addrs)

        # list all unmatched conditional nodes
        standalone_condnodes: List[Tuple[ConditionalRegion, str]] = []
        standalone_condjumps: List[ConditionalRegion] = []
        for cr in mergeable_cond_regions:
            if isinstance(cr.node, ConditionNode):
                if cr.node.true_node is not None and (cr, "true") not in used_condnodes_and_branch:
                    standalone_condnodes.append((cr, "true"))
                if cr.node.false_node is not None and (cr, "false") not in used_condnodes_and_branch:
                    standalone_condnodes.append((cr, "false"))
            elif isinstance(cr.node, ailment.Block):
                # the last statement is a conditional jump
                standalone_condjumps.append(cr)
            else:
                raise TypeError(f"Unsupported cr.node type {type(cr.node)}")

        # all conditional regions belong to the same parent node
        parents = {r.parent for r in mergeable_cond_regions + used_condnodes}
        if len(parents) != 1:
            continue

        # the hard part: ensure there are no gaps between value ranges of each conditional region

        parent = next(iter(parents))

        # build the switch-case node
        cases = []
        default_node = None

        # first let's merge all switch cases
        # to ensure proper handling of fallthrough into the default node, we add the one with a default node at the end
        switch_regions_no_default_nodes = []
        switch_regions_default_nodes = []
        for sr in switch_regions:
            if sr.node.default_node is not None and not switch_regions_default_nodes:
                switch_regions_default_nodes.append(sr)
            else:
                switch_regions_no_default_nodes.append(sr)

        for sr in switch_regions_no_default_nodes:
            for case_idx, node in sr.node.cases.items():
                cases.append((case_idx, node))
        if switch_regions_default_nodes:
            for case_idx, node in switch_regions_default_nodes[0].node.cases.items():
                cases.append((case_idx, node))
            default_node = switch_regions_default_nodes[0].node.default_node

        # then let's handle conditional nodes and jumps

        # for now, we only support two types:
        #
        # if (var == A) {
        #     goto one_case/default;
        # }
        # ... the actual switch
        #
        #  or
        #
        # if (var > A) {
        #    goto default;
        # }
        # ... the actual switch

        ok = False
        if not standalone_condnodes:
            if not standalone_condjumps:
                ok = True
            elif len(standalone_condjumps) == 1:
                condjump = standalone_condjumps[0]
                targets = set()
                if is_simple_jump_node(condjump.node, case_addrs, targets=targets) and len(targets) == 1:
                    target = next(iter(targets))
                    if condjump.op == CmpOp.EQ:
                        # which case is it jumping to?
                        existing_case_id = case_addr_to_case_id[target]
                        if existing_case_id == "default":
                            # just add it at the end
                            cases.append((condjump.value, SequenceNode(0, nodes=[])))
                        else:
                            update_switch_case_list(
                                cases,
                                existing_case_id,
                                condjump.value,
                            )
                        ok = True
                    elif condjump.op in {CmpOp.GT, CmpOp.LT}:
                        if default_node is not None and target == default_node.addr:
                            # it goes to default anyway - we don't need to do anything
                            ok = True

        if not ok:
            continue

        # build the SwitchCase node and replace old nodes in the parent node
        cases_dict = OrderedDict(cases)
        new_switchcase = SwitchCaseNode(
            switch_regions_default_nodes[0].node.switch_expr,
            cases_dict,
            default_node,
            addr=switch_regions_default_nodes[0].node.addr,
        )

        # what are we trying to replace?
        if isinstance(parent, SequenceNode):
            start_idx = None  # inclusive
            end_idx = None  # not inclusive
            for idx, node in enumerate(parent.nodes):
                if (
                    any(cr.node is node for cr, _ in standalone_condnodes)
                    or any(cr.node is node for cr in standalone_condjumps)
                    or any(cr.node is node for cr in used_condnodes)
                ):
                    if start_idx is None:
                        start_idx = idx
                    if end_idx is not None:
                        # found a gap...
                        pass
                else:
                    if start_idx is not None:
                        if end_idx is None:
                            end_idx = idx

            if start_idx is None:
                continue
            if end_idx is None:
                end_idx = len(parent.nodes)

            # we want to replace parent.nodes[start_idx : end_idx] with a SwitchCaseNode

            parent.nodes[start_idx:end_idx] = [new_switchcase]

        elif isinstance(parent, ConditionNode):
            # replace this condition node with the new SwitchCase node
            SwitchClusterReplacer(region, parent, new_switchcase)

        else:
            # unsupported for now
            continue
