"""
The steps of RegionSimplifier as RegionSimplificationPass instances.

Each pass declares whether it may change the structure of the region (nodes, gotos, labels, loop kinds, control-flow
shape) or only rewrites expressions and statements inside nodes. REGION_SIMPLIFICATION_PASSES is the ordered schedule
that RegionSimplifier runs.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING

from angr import ailment
from angr.analyses.decompiler.empty_node_remover import EmptyNodeRemover
from angr.analyses.decompiler.goto_manager import GotoManager
from angr.analyses.decompiler.jump_target_collector import JumpTargetCollector
from angr.analyses.decompiler.redundant_label_remover import RedundantLabelRemover
from angr.analyses.decompiler.semantic_naming.region_loop_counter_naming import RegionLoopCounterNaming
from angr.analyses.decompiler.structurer_nodes import LoopNode, SequenceNode
from angr.analyses.decompiler.variable_map import variable_map_of

from .cascading_cond_transformer import CascadingConditionTransformer
from .cascading_ifs import CascadingIfsRemover
from .expr_folding import (
    ExpressionCounter,
    ExpressionFolder,
    ExpressionLocation,
    InterferenceChecker,
    LoopNodeFinder,
    StoreStatementFinder,
)
from .goto import GotoSimplifier
from .if_ import IfSimplifier
from .ifelse import IfElseFlattener
from .loop import LoopSimplifier
from .switch_cluster_simplifier import SwitchClusterFinder, simplify_lowered_switches, simplify_switch_clusters
from .switch_expr_simplifier import SwitchExpressionSimplifier

if TYPE_CHECKING:
    from .region_simplifier import RegionSimplifier


class RegionSimplificationPass:
    """
    One step of RegionSimplifier.

    :ivar name:                 Name of the pass.
    :ivar changes_structure:    True if the pass may change nodes, gotos, labels, loop kinds, or the control-flow shape
                                of the region. False if it only rewrites expressions or statements inside nodes (or
                                assigns names); such passes are skipped in structure-only mode.
    """

    name: str
    changes_structure: bool

    def __init__(self, when: Callable[[RegionSimplifier], bool] | None = None):
        self._when = when

    def enabled(self, simplifier: RegionSimplifier) -> bool:
        return self._when is None or self._when(simplifier)

    def run(self, simplifier: RegionSimplifier, region: SequenceNode) -> SequenceNode:
        raise NotImplementedError

    def __repr__(self) -> str:
        return f"<{self.name}{' (structure)' if self.changes_structure else ' (expressions)'}>"


class EmptyNodeRemoval(RegionSimplificationPass):
    """
    Remove empty nodes and flip conditions with an empty true branch.
    """

    name = "EmptyNodeRemoval"
    changes_structure = True

    def run(self, simplifier: RegionSimplifier, region: SequenceNode) -> SequenceNode:
        return EmptyNodeRemover(region, simplifier.ail_manager, claripy_ast_conditions=False).result


class GotoSimplification(RegionSimplificationPass):
    """
    Remove unnecessary Jump statements and record the irreducible gotos in simplifier.goto_manager.
    """

    name = "GotoSimplification"
    changes_structure = True

    def run(self, simplifier: RegionSimplifier, region: SequenceNode) -> SequenceNode:
        gs = GotoSimplifier(region, function=simplifier.func, kb=simplifier.kb)
        simplifier.goto_manager = GotoManager(simplifier.func, gotos=gs.irreducible_gotos)
        return region


class IfSimplification(RegionSimplificationPass):
    """
    Remove conditional jumps that jump to the successor right afterwards.
    """

    name = "IfSimplification"
    changes_structure = True

    def run(self, simplifier: RegionSimplifier, region: SequenceNode) -> SequenceNode:
        IfSimplifier(region)
        return region


class LabelSimplification(RegionSimplificationPass):
    """
    Remove labels that are not referenced by any jump.
    """

    name = "LabelSimplification"
    changes_structure = True

    def run(self, simplifier: RegionSimplifier, region: SequenceNode) -> SequenceNode:
        jcl = JumpTargetCollector(region)
        RedundantLabelRemover(region, jcl.jump_targets)
        return region


class OneUseExpressionFolding(RegionSimplificationPass):
    """
    Fold expressions that are only used once into their use sites.
    """

    name = "OneUseExpressionFolding"
    changes_structure = False

    def run(self, simplifier: RegionSimplifier, region: SequenceNode) -> SequenceNode:
        loop_nodes = LoopNodeFinder(region).loop_nodes
        # a variable defined in a loop body may also be used in the loop condition or after the loop, which the
        # loop-body counter cannot see
        region_uses = ExpressionCounter(region).all_uses if loop_nodes else None
        for sub_region in [*loop_nodes, region]:
            # fold one-use expressions in each sub-region
            if isinstance(sub_region, LoopNode):
                self._fold_in_region(simplifier, sub_region.sequence_node, region_uses=region_uses)
            else:
                self._fold_in_region(simplifier, sub_region)
        return region

    @staticmethod
    def _fold_in_region(simplifier: RegionSimplifier, region, region_uses: dict[int, set] | None = None):
        # pylint:disable=unreachable
        arg_vvars = simplifier.arg_vvars
        ail_manager = simplifier.ail_manager
        expr_counter = ExpressionCounter(region)

        variable_assignments = {}
        variable_uses = {}
        variable_assignment_dependencies = {}

        # pre-process and identify folding candidates
        # for variable definitions with loads, we invoke StoreStatementFinder to see if there are any Store statements
        # before the definition site and the use site.
        var_with_loads = {}
        single_use_variables = []
        for var, outerscope_uses in expr_counter.outerscope_uses.items():
            all_uses = expr_counter.all_uses[var]
            if (
                len(outerscope_uses) == 1
                and len(all_uses) == 1
                and var in expr_counter.assignments
                and len(expr_counter.assignments[var]) == 1
                and (region_uses is None or len(region_uses.get(var, ())) <= 1)
            ):
                definition, deps, loc, has_loads = next(iter(expr_counter.assignments[var]))
                _, use_expr_loc = next(iter(outerscope_uses))
                if isinstance(use_expr_loc, ExpressionLocation) and use_expr_loc.phi_stmt:
                    # we cannot fold expressions that are used in phi statements
                    continue
                if has_loads:
                    # the definition has at least one load expression. we need to ensure there are no store statements
                    # between the definition site and the use site
                    if isinstance(use_expr_loc, ExpressionLocation):
                        use_loc = use_expr_loc.statement_location()
                    else:
                        use_loc = use_expr_loc
                    var_with_loads[var] = (loc, use_loc)
                else:
                    single_use_variables.append(var)

        store_finder = StoreStatementFinder(region, set(var_with_loads.values()))
        for var, tpl in var_with_loads.items():
            if not store_finder.has_store(*tpl):
                single_use_variables.append(var)

        for var in single_use_variables:
            definition, deps, loc, _ = next(iter(expr_counter.assignments[var]))

            # make sure all variables that var depends on has been assigned at most once
            fail = False
            for dep_var in deps:
                if arg_vvars is not None and dep_var in arg_vvars:
                    continue
                if dep_var in expr_counter.assignments and len(expr_counter.assignments[dep_var]) > 1:
                    fail = True
                    break
            if fail:
                continue

            if isinstance(definition, ailment.Stmt.SideEffectStatement):
                # clear the existing variable since we no longer write to this variable after expression folding.
                # deep_copy the ret_expr so it gets a fresh .idx; otherwise clearing its VariableMap entry (which is
                # idx-keyed) would also clear the variable of the original ret_expr, which shares the same .idx.
                if definition.ret_expr is not None:
                    new_ret_expr = definition.ret_expr.deep_copy(ail_manager)
                    definition = ailment.Stmt.SideEffectStatement(
                        definition.idx,
                        definition.expr,
                        ret_expr=new_ret_expr,
                        fp_ret_expr=definition.fp_ret_expr,
                        **definition.tags,
                    )
                    variable_map_of(ail_manager).set_variable(new_ret_expr, None)
                else:
                    definition = definition.copy()
            variable_assignments[var] = definition, loc
            variable_uses[var] = next(iter(expr_counter.outerscope_uses[var]))
            variable_assignment_dependencies[var] = deps

        # any variable definition that uses an existing to-be-removed variable cannot be folded
        all_variables_to_fold = set(variable_assignments)
        for var in all_variables_to_fold:
            if all_variables_to_fold.intersection(variable_assignment_dependencies[var]):
                del variable_assignments[var]
                del variable_uses[var]

        # ensure there is no interference between the call site and the use site
        checker = InterferenceChecker(variable_assignments, variable_uses, region, variable_map_of(ail_manager))
        for varid in checker.interfered_assignments:
            if varid in variable_assignments:
                del variable_assignments[varid]
                del variable_uses[varid]
        # fold these expressions if possible
        ExpressionFolder(variable_assignments, variable_uses, region, variable_map_of(ail_manager))
        return region


class SwitchExpressionSimplification(RegionSimplificationPass):
    """
    Move constant offsets out of switch expressions into the case values.

    Rewrites expressions only, but SwitchClusterSimplification keys switches by the variable of the switch expression,
    so it is kept in structure-only mode.
    """

    name = "SwitchExpressionSimplification"
    changes_structure = True

    def run(self, simplifier: RegionSimplifier, region: SequenceNode) -> SequenceNode:
        SwitchExpressionSimplifier(region, simplifier.ail_manager)
        return region


class SwitchClusterSimplification(RegionSimplificationPass):
    """
    Merge switch clusters and recover lowered switches.
    """

    name = "SwitchClusterSimplification"
    changes_structure = True

    def run(self, simplifier: RegionSimplifier, region: SequenceNode) -> SequenceNode:
        finder = SwitchClusterFinder(region, variable_map_of(simplifier.ail_manager))
        simplify_switch_clusters(region, finder.var2condnodes, finder.var2switches)
        simplify_lowered_switches(
            region,
            {var: v for var, v in finder.var2condnodes.items() if var not in finder.var2switches},
            simplifier.kb.functions,
            simplifier.ail_manager,
        )
        return region


class IfElseFlattening(RegionSimplificationPass):
    """
    Remove unnecessary else branches if the if branch always returns.
    """

    name = "IfElseFlattening"
    changes_structure = True

    def run(self, simplifier: RegionSimplifier, region: SequenceNode) -> SequenceNode:
        IfElseFlattener(region, simplifier.kb.functions)
        return region


class CascadingIfsRemoval(RegionSimplificationPass):
    """
    Coalesce nested single-branch ifs into one if with a conjunction.
    """

    name = "CascadingIfsRemoval"
    changes_structure = True

    def run(self, simplifier: RegionSimplifier, region: SequenceNode) -> SequenceNode:
        CascadingIfsRemover(region, simplifier.ail_manager)
        return region


class LoopSimplification(RegionSimplificationPass):
    """
    Recognize for-loops and adjust do-while conditions.
    """

    name = "LoopSimplification"
    changes_structure = True

    def run(self, simplifier: RegionSimplifier, region: SequenceNode) -> SequenceNode:
        LoopSimplifier(region, simplifier.kb.functions)
        return region


class LoopCounterNaming(RegionSimplificationPass):
    """
    Name loop counter variables.
    """

    name = "LoopCounterNaming"
    changes_structure = False

    def run(self, simplifier: RegionSimplifier, region: SequenceNode) -> SequenceNode:
        assert simplifier.variable_manager is not None
        namer = RegionLoopCounterNaming(
            region, simplifier.variable_manager, simplifier.kb.functions, variable_map_of(simplifier.ail_manager)
        )
        namer.analyze()
        namer.apply_names()
        return region


class CascadingConditionTransformation(RegionSimplificationPass):
    """
    Convert nested if-else chains into CascadingConditionNodes.
    """

    name = "CascadingConditionTransformation"
    changes_structure = True

    def run(self, simplifier: RegionSimplifier, region: SequenceNode) -> SequenceNode:
        CascadingConditionTransformer(region, simplifier.ail_manager)
        return region


def _has_arg_vvars(simplifier: RegionSimplifier) -> bool:
    return simplifier.arg_vvars is not None


def _switches(simplifier: RegionSimplifier) -> bool:
    return simplifier.simplify_switches


def _ifelse(simplifier: RegionSimplifier) -> bool:
    return simplifier.simplify_ifelse


def _loopctr_naming(simplifier: RegionSimplifier) -> bool:
    return simplifier.loopctr_naming and simplifier.variable_manager is not None


# The schedule RegionSimplifier runs, in order.
REGION_SIMPLIFICATION_PASSES: tuple[RegionSimplificationPass, ...] = (
    EmptyNodeRemoval(),
    GotoSimplification(),
    IfSimplification(),
    LabelSimplification(),
    EmptyNodeRemoval(),
    OneUseExpressionFolding(when=_has_arg_vvars),
    EmptyNodeRemoval(when=_has_arg_vvars),
    SwitchExpressionSimplification(when=_switches),
    SwitchClusterSimplification(when=_switches),
    LabelSimplification(when=_switches),
    EmptyNodeRemoval(),
    IfElseFlattening(when=_ifelse),
    CascadingIfsRemoval(),
    LoopSimplification(),
    LoopCounterNaming(when=_loopctr_naming),
    EmptyNodeRemoval(),
    CascadingConditionTransformation(),
)
