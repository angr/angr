from typing import Dict


class NodeIdManager:
    """
    Manages IDs for structurer nodes during structuring.
    """

    __slots__ = (
        "base_id",
        "next_id",
    )

    def __init__(self, base_id: int = 1):
        self.base_id = base_id
        self.next_id: Dict[int, int] = {}

    def next_node_id(self, addr: int) -> int:
        if addr not in self.next_id:
            self.next_id[addr] = self.base_id

        next_id = self.next_id[addr]
        self.next_id[addr] += 1
        return next_id
