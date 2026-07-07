"""Helpers used by the Rust ailment classes' ``__reduce__`` /
``__deepcopy__`` implementations.

``Expression`` / ``Statement`` round-trip through ``pickle`` by
serializing to bytes (``to_bytes``) and reducing to
``(reconstruct_expression | reconstruct_statement, (data,))``, which
restores them via the matching ``from_bytes`` classmethod. ``Block``
reduces to ``(cls, args)`` directly.

``copy.deepcopy`` on an AIL tree is satisfied by routing every class
through its existing ``deep_copy(manager)`` method, with a private
``_DeepcopyManager`` standing in for ``ailment.Manager``.
"""

from __future__ import annotations

import itertools


class _DeepcopyManager:
    """Minimal stand-in for ``ailment.Manager`` -- supplies fresh atom ids."""

    __slots__ = ("atom_ctr", "variable_map")

    def __init__(self):
        self.atom_ctr = itertools.count(start=10**9)
        # No side-container -- ``Rust deep_copy`` will skip the
        # ``variable_map.transfer`` step when this attribute is ``None``.
        self.variable_map = None

    def next_atom(self):
        return next(self.atom_ctr)


def deepcopy_via_deep_copy(self, memo):
    """Use ``self.deep_copy(manager)`` to satisfy ``copy.deepcopy``."""
    _ = memo  # we don't share substructures during deep_copy; ailment trees are
    # acyclic by construction, so the memo dict is unused.
    manager = _DeepcopyManager()
    return self.deep_copy(manager)


def reconstruct_expression(data: bytes):
    """Reconstruct an ``Expression`` from its ``to_bytes`` output.

    Used by ``Expression.__reduce__`` to satisfy pickle.
    """
    from angr.rustylib.ailment import Expression  # pylint:disable=import-error,import-outside-toplevel

    return Expression.from_bytes(data)


def reconstruct_statement(data: bytes):
    """Reconstruct a ``Statement`` from its ``to_bytes`` output."""
    from angr.rustylib.ailment import Statement  # pylint:disable=import-error,import-outside-toplevel

    return Statement.from_bytes(data)


__all__ = [
    "deepcopy_via_deep_copy",
    "reconstruct_expression",
    "reconstruct_statement",
]
