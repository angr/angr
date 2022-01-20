import ailment

from ....analyses import AnalysesHub
from ...analysis import Analysis
from ..empty_node_remover import EmptyNodeRemover
from .goto import GotoSimplifier
from .if_ import IfSimplifier
from .cascading_ifs import CascadingIfsRemover
from .ifelse import IfElseFlattener
from .loop import LoopSimplifier
from .expr_folding import ExpressionCounter, ExpressionFolder
from .cascading_cond_transformer import CascadingConditionTransformer


class RegionSimplifier(Analysis):
    """
    Simplifies a given region.
    """
    def __init__(self, func, region, variable_kb=None):
        self.func = func
        self.region = region
        self.variable_kb = variable_kb

        self.result = None

        self._simplify()

    def _simplify(self):
        """
        RegionSimplifier performs the following simplifications:
        - Remove redundant Gotos
        - Remove redundant If/If-else statements
        """

        r = self.region
        if self.variable_kb is not None:
            # Fold expressions that are only used once into their use sites
            r = self._fold_oneuse_expressions(r)
        # Remove empty nodes
        r = self._remove_empty_nodes(r)
        # Find nested if-else constructs and convert them into CascadingIfs
        r = self._transform_to_cascading_ifs(r)
        # Remove unnecessary Jump statements
        r = self._simplify_gotos(r)
        # Remove unnecessary jump or conditional jump statements if they jump to the successor right afterwards
        r = self._simplify_ifs(r)
        # Remove unnecessary else branches if the if branch will always return
        r = self._simplify_ifelses(r)
        #
        r = self._simplify_cascading_ifs(r)
        #
        r = self._simplify_loops(r)

        self.result = r

    #
    # Simplifiers
    #

    def _fold_oneuse_expressions(self, region):
        expr_counter = ExpressionCounter(region, self.variable_kb.variables[self.func.addr])

        variable_assignments = {}
        variable_uses = {}
        for var, uses in expr_counter.uses.items():
            if len(uses) == 1 \
                    and var in expr_counter.assignments \
                    and len(expr_counter.assignments[var]) == 1:

                definition, deps, loc = next(iter(expr_counter.assignments[var]))
                # make sure all variables that var depends on has only been assigned once
                fail = False
                for dep_var in deps:
                    if dep_var not in expr_counter.assignments or len(expr_counter.assignments[dep_var]) != 1:
                        fail = True
                        break
                if fail:
                    continue

                if isinstance(definition, ailment.Stmt.Call):
                    # clear the existing variable since we no longer write to this variable after expression folding
                    definition = definition.copy()
                    definition.ret_expr = definition.ret_expr.copy()
                    definition.ret_expr.variable = None
                variable_assignments[var] = definition, loc
                variable_uses[var] = next(iter(expr_counter.uses[var]))

        # replace them
        ExpressionFolder(variable_assignments, variable_uses, region)
        return region

    @staticmethod
    def _remove_empty_nodes(region):
        return EmptyNodeRemover(region).result

    @staticmethod
    def _transform_to_cascading_ifs(region):
        CascadingConditionTransformer(region)
        return region

    @staticmethod
    def _simplify_gotos(region):
        GotoSimplifier(region)
        return region

    @staticmethod
    def _simplify_ifs(region):
        IfSimplifier(region)
        return region

    def _simplify_ifelses(self, region):
        IfElseFlattener(region, self.kb.functions)
        return region

    @staticmethod
    def _simplify_cascading_ifs(region):
        CascadingIfsRemover(region)
        return region

    @staticmethod
    def _simplify_loops(region):
        LoopSimplifier(region)
        return region


AnalysesHub.register_default('RegionSimplifier', RegionSimplifier)
