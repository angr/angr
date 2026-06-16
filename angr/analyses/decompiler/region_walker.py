from __future__ import annotations

from .region_overlay import RegionOverlay


class RegionWalker:
    """
    A simple traverser class that walks RegionOverlay instances.
    """

    def __init__(self):
        self._parent_region = None
        self._current_region = None

    def walk(self, region: RegionOverlay):
        for node in region.graph.nodes():
            if isinstance(node, RegionOverlay):
                self._parent_region = node
                self.walk(node)
                self._parent_region = None
            else:
                self.walk_node(region, node)

    def walk_node(self, region, node):  # pylint:disable=no-self-use,unused-argument
        raise NotImplementedError("Please override this method with your own logic")
