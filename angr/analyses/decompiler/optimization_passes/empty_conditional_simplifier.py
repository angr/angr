import logging

from ... import AnalysesHub
from .structured_optimization_pass import StructuredOptimizationPass
from ..structured_codegen import CIfElse

_l = logging.getLogger(name=__name__)

class EmptyConditionalSimplifier(StructuredOptimizationPass):

    ARCHES = None
    PLATFORMS = None

    def _analyze(self, node):
        if isinstance(node, CIfElse):
            if len(node.false_node.statements) == 0:
                node.false_node = None

AnalysesHub.register_default('EmptyConditionalSimplifier', EmptyConditionalSimplifier)
