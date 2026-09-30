"""Symbol names as the portable spelling of an address.

A pattern lifted from one binary pins the addresses it saw; the same global lives
elsewhere in every other build. Naming the symbol instead lets the pattern match
wherever the loader can find that name.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from cle import Loader


def symbol_name_at(loader: Loader, addr: int) -> str | None:
    """The unversioned name of the symbol at ``addr``, or None."""
    sym = loader.find_symbol(addr)
    if sym is None or not sym.name:
        return None
    return sym.name.split("@", 1)[0]


def symbol_addr(loader: Loader, name: str) -> int | None:
    """Where ``name`` lives in this binary, or None if it has no such symbol."""
    sym = loader.find_symbol(name)
    return sym.rebased_addr if sym is not None else None
