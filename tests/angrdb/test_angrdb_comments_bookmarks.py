#!/usr/bin/env python3
# pylint:disable=no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.angrdb"  # pylint:disable=redefined-builtin

import os
import tempfile
import unittest

import angr
from angr.angrdb import AngrDB
from angr.knowledge_plugins import CommentKind
from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")


class TestAngrDBCommentsBookmarks(unittest.TestCase):
    """
    Comment kinds and bookmarks must survive an AngrDB dump/load cycle.
    """

    def test_roundtrip(self):
        bin_path = os.path.join(test_location, "x86_64", "fauxware")
        proj = angr.Project(bin_path, auto_load_libs=False)
        kb = proj.kb

        kb.comments[0x400580] = "default kind"
        kb.comments[0x400590] = "repeatable"
        kb.comments.set_kind(0x400590, CommentKind.REPEATABLE)
        kb.comments[0x4005A0] = "explicit plain"
        # simulate an explicit PLAIN at a function entry (no functions in this kb, so poke directly)
        kb.comments.kinds[0x4005A0] = CommentKind.PLAIN

        kb.bookmarks.add_bookmark(0x400710, "second")
        first, _ = kb.bookmarks.add_bookmark(0x400580, "first")

        with tempfile.TemporaryDirectory() as td:
            db_file = os.path.join(td, "test.adb")
            AngrDB(proj, nullpool=True).dump(db_file)
            proj2 = AngrDB(nullpool=True).load(db_file)
            kb2 = proj2.kb

            assert dict(kb2.comments) == dict(kb.comments)
            assert kb2.comments.kinds == {
                0x400590: CommentKind.REPEATABLE,
                0x4005A0: CommentKind.PLAIN,
            }
            assert kb2.comments.kind_of(0x400580) == CommentKind.PLAIN

            assert [(b.addr, b.label) for b in kb2.bookmarks] == [(0x400710, "second"), (0x400580, "first")]
            assert kb2.bookmarks.get_bookmark(0x400580).created_at == first.created_at

            # removals must persist across a re-dump into the same database
            kb.bookmarks.remove_bookmark(first)
            del kb.comments[0x400590]
            AngrDB(proj, nullpool=True).dump(db_file)
            proj3 = AngrDB(nullpool=True).load(db_file)
            assert [b.addr for b in proj3.kb.bookmarks] == [0x400710]
            assert 0x400590 not in proj3.kb.comments
            assert proj3.kb.comments.kinds == {0x4005A0: CommentKind.PLAIN}


if __name__ == "__main__":
    unittest.main()
