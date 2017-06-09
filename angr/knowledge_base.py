"""Representing the artifacts of a project."""

from .knowledge.data import Data
from .knowledge.function_manager import FunctionManager
from .knowledge.variable_manager import VariableManager
from .knowledge.labels import Labels


class KnowledgeBase(object):
    """Represents a "model" of knowledge about an artifact.

    Contains things like a CFG, data references, etc.
    """
    def __init__(self, project, obj):
        self._project = project
        self.obj = obj
        self.data = Data(self)
        self.functions = FunctionManager(self)
        self.variables = VariableManager(self)
        self.labels = Labels(self)
        self.comments = {}

        # a set of unresolved and a set of resolved indirect jumps
        self._unresolved_indirect_jumps = set()
        self._resolved_indirect_jumps = set()

    @property
    def callgraph(self):
        return self.functions.callgraph
