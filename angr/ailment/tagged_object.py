

class TaggedObject:
    """
    A class that takes arbitrary tags.
    """

    __slots__ = ('idx', 'tags', '_hash', )

    def __init__(self, idx, **kwargs):
        self.tags = { }
        self.idx = idx
        self._hash = None
        if kwargs:
            self.initialize_tags(kwargs)

    def initialize_tags(self, tags):
        for k, v in tags.items():
            self.tags[k] = v

    def __getattr__(self, item):
        try:
            return self.tags[item]
        except KeyError:
            return super(TaggedObject, self).__getattribute__(item)

    def __hash__(self):
        if self._hash is None:
            self._hash = self._hash_core()
        return self._hash

    def _hash_core(self):
        raise NotImplementedError()
