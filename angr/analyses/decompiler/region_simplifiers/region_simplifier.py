from __future__ import annotations
import angr.ailment as ailment

from angr.analyses.decompiler.goto_manager import GotoManager
from angr.analyses import AnalysesHub
from angr.analyses.analysis import Analysis
from angr.analyses.decompiler.empty_node_remover import EmptyNodeRemover
from angr.analyses.decompiler.jump_target_collector import JumpTargetCollector
from angr.analyses.decompiler.redundant_label_remover import RedundantLabelRemover
from angr.analyses.decompiler.structuring.structurer_nodes import LoopNode
from .goto import GotoSimplifier
from .if_ import IfSimplifier
from .cascading_ifs import CascadingIfsRemover
from .ifelse import IfElseFlattener
from .loop import LoopSimplifier
from .expr_folding import (
    ExpressionCounter,
    ExpressionFolder,
    StoreStatementFinder,
    ExpressionLocation,
    InterferenceChecker,
    LoopNodeFinder,
)
from .cascading_cond_transformer import CascadingConditionTransformer
from .switch_expr_simplifier import SwitchExpressionSimplifier
from .switch_cluster_simplifier import SwitchClusterFinder, simplify_switch_clusters, simplify_lowered_switches


class RegionSimplifier(Analysis):
    """
    Simplifies a given region.
    """

    def __init__(
        self,
        func,
        region,
        arg_vvars: set[int] | None = None,
        simplify_switches: bool = True,
        simplify_ifelse: bool = True,
    ):
        self.func = func
        self.region = region
        self.arg_vvars = arg_vvars
        self._simplify_switches = simplify_switches
        self._should_simplify_ifelses = simplify_ifelse

        self.goto_manager: GotoManager | None = None
        self.result = self.region

        self._simplify()

    def _simplify(self):
        """
        RegionSimplifier performs the following simplifications:
        - Remove redundant Gotos
        - Remove redundant If/If-else statements
        """

        r = self.region
        # Remove empty nodes
        r = self._remove_empty_nodes(r)
        # Remove unnecessary Jump statements
        r = self._simplify_gotos(r)
        # Remove unnecessary jump or conditional jump statements if they jump to the successor right afterwards
        r = self._simplify_ifs(r)
        # Remove labels that are not referenced by anything
        r = self._simplify_labels(r)
        # Remove empty nodes again
        r = self._remove_empty_nodes(r)

        if self.arg_vvars is not None:
            # Fold expressions that are only used once into their use sites
            r = self._fold_oneuse_expressions(r)
            r = self._remove_empty_nodes(r)

        if self._simplify_switches:
            # Simplify switch expressions
            r = self._simplify_switch_expressions(r)
            # Simplify switch clusters
            r = self._simplify_switch_clusters(r)
            # Again, remove labels that are not referenced by anything
            r = self._simplify_labels(r)

        # Remove empty nodes
        r = self._remove_empty_nodes(r)
        # Remove unnecessary else branches if the if branch will always return
        if self._should_simplify_ifelses:
            r = self._simplify_ifelses(r)
        #
        r = self._simplify_cascading_ifs(r)
        #
        r = self._simplify_loops(r)
        # Remove empty nodes again
        r = self._remove_empty_nodes(r)
        # Find nested if-else constructs and convert them into CascadingIfs
        r = self._transform_to_cascading_ifs(r)

        self.result = r

    #
    # Simplifiers
    #

    def _fold_oneuse_expressions(self, region):
        loop_nodes = LoopNodeFinder(region).loop_nodes
        for sub_region in [*loop_nodes, region]:
            # fold one-use expressions in each sub-region
            if isinstance(sub_region, LoopNode):
                self._fold_oneuse_expressions_in_region(sub_region.sequence_node)
            else:
                self._fold_oneuse_expressions_in_region(sub_region)
        return region

    def _fold_oneuse_expressions_in_region(self, region):
        # pylint:disable=unreachable
        expr_counter = ExpressionCounter(region)

        variable_assignments = {}
        variable_uses = {}
        variable_assignment_dependencies = {}

        # pre-process and identify folding candidates
        # for variable definitions with loads, we invoke StoreStatementFinder to see if there are any Store statements
        # before the definition site and the use site.
        var_with_loads = {}
        single_use_variables = []
        for var, uses in expr_counter.uses.items():
            if len(uses) == 1 and var in expr_counter.assignments and len(expr_counter.assignments[var]) == 1:
                definition, deps, loc, has_loads = next(iter(expr_counter.assignments[var]))
                _, use_expr_loc = next(iter(uses))
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
                if self.arg_vvars is not None and dep_var in self.arg_vvars:
                    continue
                if dep_var in expr_counter.assignments and len(expr_counter.assignments[dep_var]) > 1:
                    fail = True
                    break
            if fail:
                continue

            if isinstance(definition, ailment.Stmt.Call):
                # clear the existing variable since we no longer write to this variable after expression folding
                definition = definition.copy()
                if definition.ret_expr is not None:
                    definition.ret_expr = definition.ret_expr.copy()
                    definition.ret_expr.variable = None
            variable_assignments[var] = definition, loc
            variable_uses[var] = next(iter(expr_counter.uses[var]))
            variable_assignment_dependencies[var] = deps

        # any variable definition that uses an existing to-be-removed variable cannot be folded
        all_variables_to_fold = set(variable_assignments)
        for var in all_variables_to_fold:
            if all_variables_to_fold.intersection(variable_assignment_dependencies[var]):
                del variable_assignments[var]
                del variable_uses[var]

        # ensure there is no interference between the call site and the use site
        checker = InterferenceChecker(variable_assignments, variable_uses, region)
        for varid in checker.interfered_assignments:
            if varid in variable_assignments:
                del variable_assignments[varid]
                del variable_uses[varid]
        # fold these expressions if possible
        ExpressionFolder(variable_assignments, variable_uses, region)
        return region

    @staticmethod
    def _simplify_switch_expressions(region):
        SwitchExpressionSimplifier(region)
        return region

    def _simplify_switch_clusters(self, region):
        finder = SwitchClusterFinder(region)
        simplify_switch_clusters(region, finder.var2condnodes, finder.var2switches)
        simplify_lowered_switches(
            region,
            {var: v for var, v in finder.var2condnodes.items() if var not in finder.var2switches},
            self.kb.functions,
        )
        return region

    @staticmethod
    def _remove_empty_nodes(region):
        return EmptyNodeRemover(region, claripy_ast_conditions=False).result

    @staticmethod
    def _transform_to_cascading_ifs(region):
        CascadingConditionTransformer(region)
        return region

    def _simplify_gotos(self, region):
        simplifier = GotoSimplifier(region, function=self.func, kb=self.kb)
        self.goto_manager = GotoManager(self.func, gotos=simplifier.irreducible_gotos)
        return region

    @staticmethod
    def _simplify_ifs(region):
        IfSimplifier(region)
        return region

    @staticmethod
    def _simplify_labels(region):
        jcl = JumpTargetCollector(region)
        RedundantLabelRemover(region, jcl.jump_targets)
        return region

    def _simplify_ifelses(self, region):
        IfElseFlattener(region, self.kb.functions)
        return region

    @staticmethod
    def _simplify_cascading_ifs(region):
        CascadingIfsRemover(region)
        return region

    def _simplify_loops(self, region):
        LoopSimplifier(region, self.kb.functions)
        return region


AnalysesHub.register_default("RegionSimplifier", RegionSimplifier)
