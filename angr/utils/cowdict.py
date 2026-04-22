from __future__ import annotations
from typing import Generic, TypeVar
from typing_extensions import Self

from collections.abc import Callable
from collections import ChainMap

_MISSING = object()

K = TypeVar("K")
V = TypeVar("V")
TD = TypeVar("TD")


class ChainMapCOW(ChainMap, Generic[K, V]):
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

    def get(self, key: K, default: TD = None) -> V | TD:
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


class DefaultChainMapCOW(ChainMapCOW, Generic[K, V]):
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
