"""Representing the artifacts of a project."""

from .artifacts.data import Data
from .artifacts.function_manager import FunctionManager


class Artifact(object):
    """Represents a "model" of knowledge about an artifact.

    Contains things like a CFG, data references, etc.
    """
    def __init__(self, project, obj):
        self._project = project
        self.obj = obj
        self.data = Data(self)
        self.functions = FunctionManager(self)

    @property
    def callgraph(self):
        return self.functions.callgraph

class Artifacts(Artifact):
    """All of the artifacts of a project."""
    def __init__(self, project, program_obj, library_objs):
        Artifact.__init__(self, project, None)
        self.program = Artifact(project, program_obj)
        self.libraries = [Artifact(project, lib_obj) for lib_obj in library_objs]
