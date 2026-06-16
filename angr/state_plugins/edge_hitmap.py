from __future__ import annotations

import logging

from .plugin import SimStatePlugin

log = logging.getLogger(name=__name__)


class SimStateEdgeHitmap(SimStatePlugin):
    """
    A state plugin that stores AFL-style edge hitmap coverage data.

    This plugin is used by the Icicle engine to track edge coverage during concrete
    execution. It stores the hitmap as raw bytes, which can be efficiently passed
    to and from the Icicle emulator.

    This plugin is NOT registered as a default plugin - it must be explicitly
    added to states that need edge coverage tracking.
    """

    # Standard AFL hitmap size (64KB)
    HITMAP_SIZE = 65536

    def __init__(self, edge_hitmap: bytes | None = None):
        """
        Initialize the edge hitmap plugin.

        :param edge_hitmap: Initial edge hitmap bytes, or None to start with a zeroed hitmap.
        """
        super().__init__()
        # Initialize with zeroed hitmap if not provided
        # Allow None to be set later (e.g., from Icicle emulator)
        self.edge_hitmap: bytes | None = edge_hitmap if edge_hitmap is not None else bytes(self.HITMAP_SIZE)

    def set_state(self, state):
        pass

    @SimStatePlugin.memo
    def copy(self, memo):  # pylint: disable=unused-argument
        """
        Create a copy of the plugin.

        :param memo: Memoization dictionary to avoid duplicate copies.
        :return: A new SimStateEdgeHitmap instance with a copy of the hitmap.
        """
        # bytes are immutable, so we can share the reference
        return SimStateEdgeHitmap(edge_hitmap=self.edge_hitmap)

    def merge(self, others, merge_conditions, common_ancestor=None):  # pylint: disable=unused-argument
        """
        Merge multiple hitmap plugins.

        For coverage tracking, we OR the hitmaps together to preserve all
        observed edges.

        :param others: Other plugin instances to merge with.
        :param merge_conditions: Symbolic conditions for each merge branch.
        :param common_ancestor: Common ancestor plugin instance.
        :return: True if merge was successful.
        """
        for other in others:
            if len(self.edge_hitmap) == len(other.edge_hitmap):
                # OR the hitmaps together to combine coverage
                self.edge_hitmap = bytes(a | b for a, b in zip(self.edge_hitmap, other.edge_hitmap, strict=True))
            else:
                log.warning("Cannot merge edge hitmaps of different sizes")
        return True

    def widen(self, others):  # pylint: disable=unused-argument
        """
        Widening operation for static analysis.

        :param others: Other plugin instances.
        :return: False, widening is not meaningful for hitmaps.
        """
        log.warning("Widening is not implemented for edge hitmap")
        return False
