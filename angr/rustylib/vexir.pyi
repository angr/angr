from typing import Any

class IrBlock:
    """
    An owned, statement-level copy of a lifted VEX IRSB: statements 1:1 with ``pyvex.IRSB.statements``.
    """

    addr: int
    size: int
    jumpkind: str
    instructions: int
    instruction_addresses: list[int]

    def to_tuple(self) -> tuple[list[tuple[Any, ...]], Any, list[str]]:
        """``(statements, next, tyenv)`` as nested tuples; floats are given as their IEEE bits."""
