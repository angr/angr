from ...analysis import Analysis
from .goto import GotoSimplifier
from .if_ import IfSimplifier
from .cascading_ifs import CascadingIfsRemover
from .ifelse import IfElseFlattener
from .loop import LoopSimplifier


class RegionSimplifier(Analysis):
    def __init__(self, region):
        self.region = region

        self.result = None

        self._simplify()

    def _simplify(self):
        """
        RegionSimplifier performs the following simplifications:
        - Remove redundant Gotos
        - Remove redundant If/If-else statements
        """

        r = self.region
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


from ....analyses import AnalysesHub
AnalysesHub.register_default('RegionSimplifier', RegionSimplifier)