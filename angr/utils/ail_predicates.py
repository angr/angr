"""Native fast paths for the pure-predicate AIL walkers.

Four ``AILBlockViewer`` subclasses in the decompiler hot path exist only to
answer a yes/no question about an AIL subtree, with no Python callback anywhere
in the walk (see ``native/angr/src/ailment/predicates.rs``). Since the AIL
marker classes dispatch ``isinstance`` purely on the variant tag, each of those
questions is a bitmask test on the node kind, so the whole walk can run
natively and return a single ``bool``.

Every wrapper here falls back to the Python walker when the native path returns
``None`` (a non-native AIL node -- e.g. ``IncompleteSwitchCaseHeadStatement``).

``ANGR_NATIVE_PREDICATES`` selects the implementation:

* unset / ``1`` -- native, with Python fallback (default)
* ``0``         -- Python walkers only
* ``shadow``    -- run both and assert they agree
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

from angr.rustylib.ailment import has_blacklisted_exprs as _n_blacklisted  # pylint:disable=import-error
from angr.rustylib.ailment import has_call_expr as _n_has_call  # pylint:disable=import-error
from angr.rustylib.ailment import has_nonwhitelisted_exprs as _n_nonwhitelisted  # pylint:disable=import-error
from angr.rustylib.ailment import has_reference_to_vvar as _n_ref_to_vvar  # pylint:disable=import-error
from angr.rustylib.ailment import stmt_vvar_use_ids  # noqa: F401  # pylint:disable=import-error

if TYPE_CHECKING:
    from angr.ailment import Expression, Statement

_MODE = os.environ.get("ANGR_NATIVE_PREDICATES", "1")
NATIVE = _MODE != "0"
SHADOW = _MODE == "shadow"


def _compute_kinds_mask(types: tuple[type, ...]) -> int | None:
    mask = 0
    for t in types:
        ints = getattr(t, "_match_kind_ints", None)
        if ints is None:
            return None
        for k in ints:
            mask |= 1 << int(k)
    return mask


# The whitelist / blacklist tuples are module-level constants reused on every call, so the mask is computed once per
# distinct tuple. Recomputing it per call costs more than the native walk it enables.
_MASK_CACHE: dict[tuple[type, ...], int | None] = {}


def kinds_mask(types: tuple[type, ...]) -> int | None:
    """
    OR together the ``ExpressionKind`` bits every marker class in ``types`` matches. Returns ``None`` if any entry is
    not a marker class, in which case the native path is not applicable.
    """
    try:
        return _MASK_CACHE[types]
    except KeyError:
        pass
    except TypeError:  # unhashable -- not a tuple of classes
        return _compute_kinds_mask(types)
    mask = _compute_kinds_mask(types)
    _MASK_CACHE[types] = mask
    return mask


def _check(native: bool | None, py_fn, *args) -> bool:
    """Resolve a native result against the Python walker per the active mode."""
    if native is None:
        return py_fn(*args)
    if not SHADOW:
        return native
    expected = py_fn(*args)
    if native != expected:
        raise AssertionError(f"native AIL predicate mismatch: native={native} python={expected} args={args!r}")
    return expected


#
# AILWhitelistExprTypeWalker
#


def has_nonwhitelisted_exprs(node: Expression | Statement, whitelist: tuple[type, ...], py_fn) -> bool:
    """
    ``AILWhitelistExprTypeWalker(whitelist)`` run over ``node``: is any expression kind outside ``whitelist``?
    """
    if NATIVE:
        mask = kinds_mask(whitelist)
        if mask is not None:
            return _check(_n_nonwhitelisted(node, mask), py_fn, node, whitelist)
    return py_fn(node, whitelist)


#
# AILBlacklistExprTypeWalker
#


def has_blacklisted_exprs(
    node: Expression | Statement,
    blacklist: tuple[type, ...],
    py_fn,
    skip_if_contains_vvar: int | None = None,
) -> bool:
    """
    ``AILBlacklistExprTypeWalker(blacklist, skip_if_contains_vvar)`` run over ``node``.
    """
    if NATIVE:
        mask = kinds_mask(blacklist)
        if mask is not None:
            return _check(
                _n_blacklisted(node, mask, skip_if_contains_vvar),
                py_fn,
                node,
                blacklist,
                skip_if_contains_vvar,
            )
    return py_fn(node, blacklist, skip_if_contains_vvar)


#
# HasCallExprWalker
#


def has_call_expr(node: Expression | Statement, py_fn) -> bool:
    """
    ``HasCallExprWalker`` run over ``node``: does it contain a ``Call`` / ``FunctionLikeMacro`` expression or a
    ``SideEffectStatement``?
    """
    if NATIVE:
        return _check(_n_has_call(node), py_fn, node)
    return py_fn(node)


#
# AILReferenceFinder
#


def has_reference_to_vvar(node: Statement, vvar_id: int, py_fn) -> bool:
    """
    ``AILReferenceFinder(vvar_id)`` run over ``node``: does it contain ``Reference(VirtualVariable(vvar_id))``?
    """
    if NATIVE:
        return _check(_n_ref_to_vvar(node, vvar_id), py_fn, node, vvar_id)
    return py_fn(node, vvar_id)
