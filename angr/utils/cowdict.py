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
    """

    def __init__(self, *args, collapse_threshold=None):
        super().__init__(*args)
        self.dirty = False
        self.collapse_threshold = collapse_threshold
        self._deleted: set = set()

    def copy(self) -> Self:
        self.dirty = True
        return self

    def __getitem__(self, key: K) -> V:
        if key in self._deleted:
            raise KeyError(key)
        return super().__getitem__(key)

    def __contains__(self, key) -> bool:
        if key in self._deleted:
            return False
        return super().__contains__(key)

    def __setitem__(self, key: K, value: V) -> None:
        self._deleted.discard(key)
        super().__setitem__(key, value)

    def __delitem__(self, key: K):
        if key in self._deleted or not super().__contains__(key):
            raise KeyError(key)
        # Remove from maps[0] if present
        self.maps[0].pop(key, None)
        # Mark as deleted so parent maps don't expose it
        self._deleted.add(key)

    def pop(self, key: K, *args) -> V:  # type: ignore[reportIncompatibleMethodOverride]
        if key in self._deleted:
            if args:
                return args[0]
            raise KeyError(key)
        try:
            value = super().__getitem__(key)
        except KeyError:
            if args:
                return args[0]
            raise
        # Remove from maps[0] if present
        self.maps[0].pop(key, None)
        # Mark as deleted so parent maps don't expose it
        self._deleted.add(key)
        return value

    def get[TD](self, key: K, default: TD = None) -> V | TD:
        if key in self._deleted:
            return default
        return super().get(key, default)

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
        if m is None:
            m = {}
        return ChainMapCOW(m, *self.maps, collapse_threshold=self.collapse_threshold)

    def clean(self) -> ChainMapCOW[K, V]:
        if self.dirty:
            # collapse?
            if self.collapse_threshold is not None and len(self.maps) >= self.collapse_threshold:
                collapsed = {}
                for m in reversed(self.maps):
                    collapsed.update(m)
                for k in self._deleted:
                    collapsed.pop(k, None)
                return ChainMapCOW(collapsed, collapse_threshold=self.collapse_threshold)
            ch = self.new_child()
            ch._deleted = set(self._deleted)
            return ch
        return self


class DefaultChainMapCOW[K, V](ChainMapCOW):
    """
    Implements a copy-on-write version of ChainMap with default values that supports auto-collapsing.
    """

    def __init__(self, *args, default_factory: Callable, collapse_threshold=None):
        super().__init__(*args, collapse_threshold=collapse_threshold)
        self.default_factory = default_factory

    def __getitem__(self, key: K) -> V:
        try:
            return super().__getitem__(key)
        except KeyError:
            self.__setitem__(key, self.default_factory())
            return super().__getitem__(key)

    def new_child(self, m=None, **kwargs) -> DefaultChainMapCOW[K, V]:
        if m is None:
            m = kwargs
        elif kwargs:
            m.update(kwargs)
        return DefaultChainMapCOW(
            m, *self.maps, default_factory=self.default_factory, collapse_threshold=self.collapse_threshold
        )

    def clean(self) -> DefaultChainMapCOW[K, V]:
        if self.dirty:
            # collapse?
            if self.collapse_threshold is not None and len(self.maps) >= self.collapse_threshold:
                collapsed = {}
                for m in reversed(self.maps):
                    collapsed.update(m)
                for k in self._deleted:
                    collapsed.pop(k, None)
                return DefaultChainMapCOW(
                    collapsed, default_factory=self.default_factory, collapse_threshold=self.collapse_threshold
                )
            r = self.new_child()
            r._deleted = set(self._deleted)
            return r
        return self
