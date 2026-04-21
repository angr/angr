from __future__ import annotations
from collections import ChainMap

_MISSING = object()


class ChainMapCOW(ChainMap):
    """
    Implements a copy-on-write version of ChainMap that supports auto-collapsing.

    Tracks logically deleted keys via a _deleted set so that pop() and del
    work correctly even when keys live in parent maps.
    """

    def __init__(self, *args, collapse_threshold=None):
        super().__init__(*args)
        self.dirty = False
        self.collapse_threshold = collapse_threshold
        self._deleted: set = set()

    def copy(self):
        self.dirty = True
        return self

    def __getitem__(self, key):
        if key in self._deleted:
            raise KeyError(key)
        return super().__getitem__(key)

    def __contains__(self, key):
        if key in self._deleted:
            return False
        return super().__contains__(key)

    def __setitem__(self, key, value):
        self._deleted.discard(key)
        super().__setitem__(key, value)

    def __delitem__(self, key):
        if key in self._deleted or not super().__contains__(key):
            raise KeyError(key)
        # Remove from maps[0] if present
        self.maps[0].pop(key, None)
        # Mark as deleted so parent maps don't expose it
        self._deleted.add(key)

    def pop(self, key, *args):
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

    def get(self, key, default=None):
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

    def clean(self):
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
            ch.collapse_threshold = self.collapse_threshold
            ch._deleted = set(self._deleted)
            return ch
        return self


class DefaultChainMapCOW(ChainMapCOW):
    """
    Implements a copy-on-write version of ChainMap with default values that supports auto-collapsing.
    """

    def __init__(self, *args, default_factory=None, collapse_threshold=None):
        super().__init__(*args, collapse_threshold=collapse_threshold)
        self.default_factory = default_factory

    def __getitem__(self, key):
        try:
            return super().__getitem__(key)
        except KeyError:
            self.__setitem__(key, self.default_factory())
            return super().__getitem__(key)

    def clean(self):
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
            r.default_factory = self.default_factory
            r.collapse_threshold = self.collapse_threshold
            r._deleted = set(self._deleted)
            return r
        return self
