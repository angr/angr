"""Representing a model of a program."""

from .data import Data
from .code import Code


class Model(object):
    """Represents a "model" of knowledge about a program.

    Contains things like a CFG, data references, etc.
    """
    def __init__(self, project):
        self._project = project
        self.data = Data(self)
        self.code = Code(self)
