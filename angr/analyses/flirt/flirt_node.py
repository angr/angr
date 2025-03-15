from __future__ import annotations
from .flirt_module import FlirtModule


class FlirtNode:
    """
    Describes a tree node in the FLIRT signature tree.
    """

    __slots__ = ("children", "length", "modules", "pattern")

    def __init__(self, children: list[FlirtNode], modules: list[FlirtModule], length: int, pattern: list[int]):
        self.children = children
        self.modules = modules
        self.length = length
        self.pattern = pattern

    @property
    def leaf(self) -> bool:
        return not self.children

    def __repr__(self) -> str:
        return f"<FlirtNode length={self.length} leaf={self.leaf}>"
