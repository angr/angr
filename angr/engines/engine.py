from __future__ import annotations

import abc
from typing import Generic, TypeVar


import angr

StateType = TypeVar("StateType")
ResultType = TypeVar("ResultType")
DataType_co = TypeVar("DataType_co", covariant=True)


class SimEngine(Generic[StateType, ResultType], metaclass=abc.ABCMeta):
    """
    A SimEngine is a type which understands how to perform execution on a state.
    """

    state: StateType

    def __init__(self, project: angr.Project, support_multiblock_lifting: bool = False):
        self.project = project
        self.arch = self.project.arch
        self._support_multiblock_lifting = support_multiblock_lifting

    def __getstate__(self):
        return (self.project,)

    def __setstate__(self, state):
        self.project = state[0]

    @property
    def support_multiblock_lifting(self) -> bool:
        """
        Whether this engine supports multiblock lifting.
        """
        return self._support_multiblock_lifting
