
from ...analysis import Analysis
from ..structured_codegen import CIfElse, CStatements, CFunctionCall

class StructuredOptimizationPass(Analysis):

    ARCHES = [ ]
    PLATFORMS = [ ]

    def __init__(self, func, cfunc):
        self._func = func
        self._cfunc = cfunc

        self.walk()

    def walk(self):
        seen = set()
        worklist = [self._cfunc]
        while worklist:
            node = worklist.pop(0)

            if node in seen:
                continue
            else:
                seen.add(node)

            self._analyze(node)
            if isinstance(node, CIfElse):
                worklist.append(node.true_node)
                worklist.append(node.false_node)
            elif isinstance(node, CStatements):
                worklist.extend(node.statements)
            elif hasattr(node, 'statements'):
                assert type(node.statements) is not list
                worklist.append(node.statements)


    def _analyze(self, node):
        raise NotImplementedError
