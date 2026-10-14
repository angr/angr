from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Sequence

    from .c import CStatement
    from .go import GoStatement


def first_stmt_addr(statements: Sequence[CStatement] | Sequence[GoStatement]) -> int | None:
    """
    The address of the first statement that has one: a nested statement list's address or an instruction address tag.
    """

    from .c import CStatements  # pylint: disable=import-outside-toplevel
    from .go import GoStatements  # pylint: disable=import-outside-toplevel

    for stmt in statements:
        if isinstance(stmt, (CStatements, GoStatements)):
            addr = stmt.addr
        else:
            addr = stmt.tags.get("ins_addr") if stmt.tags is not None else None
        return addr
    return None
