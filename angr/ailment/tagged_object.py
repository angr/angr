from __future__ import annotations


class TaggedObject:
    """
    A class that takes arbitrary tags.
    """

    __slots__ = (
        "_hash",
        "_tags",
        "idx",
    )

    def __init__(self, idx: int | None, **kwargs):
        self._tags = None
        self.idx = idx
        self._hash = None
        if kwargs:
            self.initialize_tags(kwargs)

    def initialize_tags(self, tags):
        self._tags = {}
        for k, v in tags.items():
            self._tags[k] = v

    def __hash__(self) -> int:
        if self._hash is None:
            self._hash = self._hash_core()
        return self._hash

    def _hash_core(self):
        raise NotImplementedError

    @property
    def tags(self) -> dict:
        if not self._tags:
            self._tags = {}
        return self._tags
