from typing import Dict


class TaggedObject:
    """
    A class that takes arbitrary tags.
    """

    __slots__ = (
        "idx",
        "_tags",
        "_hash",
    )

    def __init__(self, idx, **kwargs):
        self._tags = None
        self.idx = idx
        self._hash = None
        if kwargs:
            self.initialize_tags(kwargs)

    def initialize_tags(self, tags):
        self._tags = {}
        for k, v in tags.items():
            self._tags[k] = v

    def __getattr__(self, item):
        try:
            return self.tags[item]
        except KeyError:
            return super().__getattribute__(item)

    def __new__(cls, *args, **kwargs):  # pylint:disable=unused-argument
        """Create a new instance and set `_tags` attribute.

        Since TaggedObject override `__getattr__` method and try to access the
        `_tags` attribute, infinite recursion could occur if `_tags` not ready
        to exists.

        This behavior causes an infinite recursion error when copying
        `TaggedObject` with `copy.deepcopy`.

        Hence, we set `_tags` attribute here to prevent this problem.
        """
        self = super().__new__(cls)
        self._tags = None
        return self

    def __hash__(self):
        if self._hash is None:
            self._hash = self._hash_core()
        return self._hash

    def _hash_core(self):
        raise NotImplementedError()

    @property
    def tags(self) -> Dict:
        if not self._tags:
            self._tags = {}
        return self._tags
