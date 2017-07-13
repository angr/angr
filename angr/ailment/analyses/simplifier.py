
from angr import Analysis, register_analysis

from ..block import Block
from ..statement import Assignment


class Simplifier(Analysis):
    def __init__(self, block):
        """

        :param Block block:
        """

        self.block = block

        self._analyze()

    def _analyze(self):

        self._simplify_block(self.block)

    def _simplify_block(self, block):

        # reaching definition analysis
        rd = self.project.analyses.ReachingDefinitions(block=block)

        # propagator
        self.project.analyses.Propagator(block=block, reaching_definitions=rd)


register_analysis(Simplifier, 'ASimplifier')
