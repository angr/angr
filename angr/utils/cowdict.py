from collections import ChainMap


class ChainMapCOW(ChainMap):
    """
    Implements a copy-on-write version of ChainMap that supports auto-collapsing.
    """

    def __init__(self, *args, collapse_threshold=None):
        super().__init__(*args)
        self.dirty = False
        self.collapse_threshold = collapse_threshold

    def copy(self):
        self.dirty = True
        return self

    def clean(self):
        if self.dirty:
            # collapse?
            if self.collapse_threshold is not None and len(self.maps) >= self.collapse_threshold:
                collapsed = {}
                for m in reversed(self.maps):
                    collapsed.update(m)
                return ChainMapCOW(collapsed, collapse_threshold=self.collapse_threshold)
            ch = self.new_child()
            ch.collapse_threshold = self.collapse_threshold
            return ch
        else:
            return self


class DefaultChainMapCOW(ChainMapCOW):
    """
    Implements a copy-on-write version of ChainMap with default values that supports auto-collapsing.
    """

    def __init__(self, default_factory, *args, collapse_threshold=None):
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
                return DefaultChainMapCOW(collapsed, collapse_threshold=self.collapse_threshold)
            r = self.new_child()
            r.default_factory = self.default_factory
            r.collapse_threshold = self.collapse_threshold
            return r
        else:
            return self
