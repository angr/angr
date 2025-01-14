from __future__ import annotations

from angr.analyses.decompiler.goto_manager import GotoManager
from angr.analyses import AnalysesHub
from angr.analyses.analysis import Analysis
from angr.analyses.decompiler.empty_node_remover import EmptyNodeRemover
from angr.analyses.decompiler.jump_target_collector import JumpTargetCollector
from angr.analyses.decompiler.redundant_label_remover import RedundantLabelRemover
from .goto import GotoSimplifier
from .if_ import IfSimplifier
from .cascading_ifs import CascadingIfsRemover
from .ifelse import IfElseFlattener
from .loop import LoopSimplifier
from .cascading_cond_transformer import CascadingConditionTransformer
from .switch_expr_simplifier import SwitchExpressionSimplifier
from .switch_cluster_simplifier import SwitchClusterFinder, simplify_switch_clusters, simplify_lowered_switches


class RegionSimplifier(Analysis):
    """
    Simplifies a given region.
    """

    def __init__(self, func, region, variable_kb=None, simplify_switches: bool = True, simplify_ifelse: bool = True):
        self.func = func
        self.region = region
        self.variable_kb = variable_kb
        self._simplify_switches = simplify_switches
        self._should_simplify_ifelses = simplify_ifelse

        self.goto_manager: GotoManager | None = None
        self.result = None

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
