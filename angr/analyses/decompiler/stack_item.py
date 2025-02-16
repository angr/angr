from __future__ import annotations

from enum import Enum


class StackItemType(Enum):
    """
    Enum for the type of stack items.
    """

    UNKNOWN = 0
    SAVED_BP = 1
    SAVED_REGS = 2
    ARGUMENT = 3
    RET_ADDR = 4
    STACK_CANARY = 5


class StackItem:
    """
    A stack item describes a piece of data that is stored on the stack at a certain offset (usually negative).
    """

    offset: int
    size: int
    name: str
    item_type: StackItemType

    def __init__(self, offset: int, size: int, name: str, item_type: StackItemType = StackItemType.UNKNOWN):
        self.offset = offset
        self.size = size
        self.name = name
        self.item_type = item_type

    def __repr__(self):
        return f"<StackItem {self.name} {self.item_type!s} at {self.offset:#x} ({self.size}b)>"
