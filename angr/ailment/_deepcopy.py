"""Helpers used by the Rust ailment classes' ``__deepcopy__`` implementations.

``copy.deepcopy`` on an AIL tree is satisfied by routing every class through its existing ``deep_copy(manager)``
method, with a private ``_DeepcopyManager`` standing in for ``ailment.Manager``.
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
    # we don't share substructures during deep_copy; ailment trees are acyclic by construction, so the memo dict is
    # unused.
    _ = memo
    manager = _DeepcopyManager()
    return self.deep_copy(manager)


__all__ = [
    "deepcopy_via_deep_copy",
]
