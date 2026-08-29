from __future__ import annotations

import unittest

from angr.utils.graph import ContainerNode, SCCPlaceholder, TemporaryNode
from angr.utils.hashing import stable_hash


class TestGraphHelperNodeHashes(unittest.TestCase):
    """These hashes decide dominator-tree and SCC iteration order, which reaches Phoenix's refinement
    decisions. hash() over a str is PYTHONHASHSEED-randomised, so they must not use it."""

    def test_hashes_are_seed_independent(self):
        assert hash(TemporaryNode("x")) == stable_hash(("TemporaryNode", "x"))
        assert hash(SCCPlaceholder(3, 0x400000)) == stable_hash(("scc_placeholder", 3))
        obj = TemporaryNode("wrapped")
        assert hash(ContainerNode(obj)) == stable_hash(("CN", hash(obj)))

    def test_container_node_equality_is_identity_on_the_wrapped_object(self):
        a, b = TemporaryNode("x"), TemporaryNode("x")
        assert a == b  # TemporaryNode compares by label
        # ContainerNode still separates them: it compares the wrapped object by identity
        assert ContainerNode(a) != ContainerNode(b)
        assert ContainerNode(a) == ContainerNode(a)
        assert len({ContainerNode(a), ContainerNode(b)}) == 2


if __name__ == "__main__":
    unittest.main()
