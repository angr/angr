"""Representing the artifacts of a project."""

from .data import Data
from .code import Code


class Artifact(object):
    """Represents a "model" of knowledge about an artifact.

    Contains things like a CFG, data references, etc.
    """
    def __init__(self, project, obj):
        self._project = project
        self.obj = obj
        self.data = Data(self)
        self.code = Code(self)

    @property
    def functions(self):
        """The functions of the artifact."""
        return []

    @property
    def blocks(self):
        """The blocks of the artifact."""
        return []


class Artifacts(object):
    """All of the artifacts of a project."""
    def __init__(self, project, program_obj, library_objs):
        self._project = project
        self.program = Artifact(project, program_obj)
        self.libraries = [Artifact(project, lib_obj) for lib_obj in library_objs]

    @property
    def functions(self):
        """All of the functions of a project."""
        return [func for artifact in [self.program] + self.libraries for func in artifact.functions]

    @property
    def blocks(self):
        """All of the blocks of a project."""
        return [block for artifact in [self.program] + self.libraries for block in artifact.blocks]
