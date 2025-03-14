from __future__ import annotations


class FlirtFunction:
    """
    Describes a function object in a FLIRT signature.
    """

    __slots__ = (
        "collision",
        "local",
        "name",
        "offset",
    )

    def __init__(self, name: str, offset: int, local: bool, collision: bool):
        self.name = name
        self.offset = offset
        self.local = local
        self.collision = collision
