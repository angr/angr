from __future__ import annotations

from collections import ChainMap
from collections.abc import Callable
from typing import Self

_MISSING = object()


def merge_candidate_keys(a: ChainMapCOW, b: ChainMapCOW) -> set:
    """
    Return the keys that may differ between two COW chain maps which (typically) descend
    from a common ancestor and therefore share a common suffix of layer objects.

    A key whose binding lives entirely in the shared suffix -- an identical ``maps`` entry
    (by identity) that is not shadowed by a deletion in either map -- resolves to the same
    value in both maps, so unioning them is always a no-op and the key is omitted. The
    result is the union of the keys held in each map's non-shared "head" layers, plus the
    keys either map has logically deleted: a deleted key may still be bound in the other
    map's shared suffix and therefore needs to be resurrected by a merge.
    """
    am, bm = a.maps, b.maps
    i, j = len(am) - 1, len(bm) - 1
    while i >= 0 and j >= 0 and am[i] is bm[j]:
        i -= 1
        j -= 1
    cand: set = set()
    for m in am[: i + 1]:
        cand.update(m)
    for m in bm[: j + 1]:
        cand.update(m)
    cand |= a._deleted
    cand |= b._deleted
    return cand


class ChainMapCOW[K, V](ChainMap):
    """
    Implements a copy-on-write version of ChainMap that supports auto-collapsing.

    Tracks logically deleted keys via a _deleted set so that pop() and del work correctly even when keys live in parent
    maps.

    Performance note: We deliberately re-implement the ChainMap walk for better performance. ``ChainMap.__getitem__``
    raises a ``KeyError`` for every layer that misses, and ``ChainMap.get`` walks the whole chain twice
    (``__contains__`` and ``__getitem__``). We avoid both by inlining ``if key in mapping``.

    We may revisit the implementation in the future when the performance of ChainMap improves.
    """

    __slots__ = ("_deleted", "collapse_threshold", "dirty", "maps")

    def __init__(self, *args, collapse_threshold=None):
        self.maps = list(args) or [{}]
        self.dirty = False
        self.collapse_threshold = collapse_threshold
        self._deleted: set = set()

    def copy(self) -> Self:
        self.dirty = True
        return self

    def __getitem__(self, key: K) -> V:
        if key in self._deleted:
            raise KeyError(key)
        for mapping in self.maps:
            if key in mapping:
                return mapping[key]
        return self.__missing__(key)

    def __contains__(self, key) -> bool:
        if key in self._deleted:
            return False
        # an explicit loop, not any(), on purpose: this is hot and any() costs a generator frame per call
        for mapping in self.maps:  # noqa: SIM110
            if key in mapping:
                return True
        return False

    def __setitem__(self, key: K, value: V) -> None:
        if self._deleted:
            self._deleted.discard(key)
        self.maps[0][key] = value

    def __delitem__(self, key: K):
        if key in self._deleted:
            raise KeyError(key)
        for mapping in self.maps:
            if key in mapping:
                break
        else:
            raise KeyError(key)
        # Remove from maps[0] if present
        self.maps[0].pop(key, None)
        # Mark as deleted so parent maps don't expose it
        self._deleted.add(key)

    def pop(self, key: K, *args) -> V:  # type: ignore[reportIncompatibleMethodOverride]
        if key not in self._deleted:
            for mapping in self.maps:
                if key in mapping:
                    value = mapping[key]
                    # Remove from maps[0] if present
                    self.maps[0].pop(key, None)
                    # Mark as deleted so parent maps don't expose it
                    self._deleted.add(key)
                    return value
        if args:
            return args[0]
        raise KeyError(key)

    def get[TD](self, key: K, default: TD = None) -> V | TD:
        if key in self._deleted:
            return default
        for mapping in self.maps:
            if key in mapping:
                return mapping[key]
        return default

    def __iter__(self):
        seen = set(self._deleted)
        for mapping in reversed(self.maps):
            for key in mapping:
                if key not in seen:
                    yield key
                    seen.add(key)

    def __len__(self):
        return len(set().union(*self.maps) - self._deleted)

    def new_child(self, m=None) -> ChainMapCOW[K, V]:
        obj = ChainMapCOW.__new__(ChainMapCOW)
        obj.maps = [{} if m is None else m, *self.maps]
        obj.dirty = False
        obj.collapse_threshold = self.collapse_threshold
        obj._deleted = set()
        return obj

    def _collapsed_dict(self) -> dict:
        collapsed: dict = {}
        for m in reversed(self.maps):
            collapsed.update(m)
        for k in self._deleted:
            collapsed.pop(k, None)
        return collapsed

    def clean(self) -> ChainMapCOW[K, V]:
        if not self.dirty:
            return self
        obj = ChainMapCOW.__new__(ChainMapCOW)
        obj.dirty = False
        obj.collapse_threshold = self.collapse_threshold
        # collapse?
        if self.collapse_threshold is not None and len(self.maps) >= self.collapse_threshold:
            obj.maps = [self._collapsed_dict()]
            obj._deleted = set()
        else:
            obj.maps = [{}, *self.maps]
            obj._deleted = set(self._deleted)
        return obj


class DefaultChainMapCOW[K, V](ChainMapCOW):
    """
    Implements a copy-on-write version of ChainMap with default values that supports auto-collapsing.
    """

    __slots__ = ("default_factory",)

    def __init__(self, *args, default_factory: Callable, collapse_threshold=None):
        super().__init__(*args, collapse_threshold=collapse_threshold)
        self.default_factory = default_factory

    def __getitem__(self, key: K) -> V:
        deleted = self._deleted
        if key not in deleted:
            for mapping in self.maps:
                if key in mapping:
                    return mapping[key]
        else:
            deleted.discard(key)
        value = self.default_factory()
        self.maps[0][key] = value
        return value

    def new_child(self, m=None, **kwargs) -> DefaultChainMapCOW[K, V]:
        if m is None:
            m = kwargs
        elif kwargs:
            m.update(kwargs)
        obj = DefaultChainMapCOW.__new__(DefaultChainMapCOW)
        obj.maps = [m, *self.maps]
        obj.dirty = False
        obj.collapse_threshold = self.collapse_threshold
        obj.default_factory = self.default_factory
        obj._deleted = set()
        return obj

    def clean(self) -> DefaultChainMapCOW[K, V]:
        if not self.dirty:
            return self
        obj = DefaultChainMapCOW.__new__(DefaultChainMapCOW)
        obj.dirty = False
        obj.collapse_threshold = self.collapse_threshold
        obj.default_factory = self.default_factory
        # collapse?
        if self.collapse_threshold is not None and len(self.maps) >= self.collapse_threshold:
            obj.maps = [self._collapsed_dict()]
            obj._deleted = set()
        else:
            obj.maps = [{}, *self.maps]
            obj._deleted = set(self._deleted)
        return obj
