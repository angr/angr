#!/usr/bin/env python3
# pylint:disable=no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.knowledge_plugins"  # pylint:disable=redefined-builtin

import unittest

import angr
from angr.knowledge_plugins import CommentKind
from angr.knowledge_plugins.xrefs import XRef, XRefType


class CommentsTests(unittest.TestCase):
    """
    Tests for comment kinds and repeatable comments in the Comments knowledge plugin.
    """

    def _project(self):
        proj = angr.load_shellcode(b"\x31\xc0\xc3", arch="AMD64", load_address=0x1000)
        proj.analyses.CFGFast(force_complete_scan=False)
        assert 0x1000 in proj.kb.functions
        return proj

    def test_kind_defaults(self):
        proj = self._project()
        comments = proj.kb.comments
        comments[0x1000] = "function comment"
        comments[0x1002] = "plain comment"

        assert comments.kind_of(0x1000) == CommentKind.FUNCTION
        assert comments.kind_of(0x1002) == CommentKind.PLAIN

    def test_explicit_kinds(self):
        proj = self._project()
        comments = proj.kb.comments
        comments[0x1000] = "c"
        comments[0x1002] = "c"

        # an explicit PLAIN at a function entry overrides the FUNCTION default and is kept
        comments.set_kind(0x1000, CommentKind.PLAIN)
        assert comments.kind_of(0x1000) == CommentKind.PLAIN
        assert 0x1000 in comments.kinds

        # an explicit PLAIN elsewhere is the default and is not stored
        comments.set_kind(0x1002, CommentKind.PLAIN)
        assert 0x1002 not in comments.kinds

        comments.set_kind(0x1002, CommentKind.REPEATABLE)
        assert comments.kind_of(0x1002) == CommentKind.REPEATABLE

        comments.set_kind(0x1000, None)
        assert comments.kind_of(0x1000) == CommentKind.FUNCTION

    def test_removing_comment_drops_kind(self):
        proj = self._project()
        comments = proj.kb.comments
        comments[0x1002] = "c"
        comments.set_kind(0x1002, CommentKind.REPEATABLE)

        del comments[0x1002]
        assert 0x1002 not in comments.kinds

        comments[0x1002] = "c"
        comments.set_kind(0x1002, CommentKind.REPEATABLE)
        comments.pop(0x1002)
        assert 0x1002 not in comments.kinds

        comments[0x1002] = "c"
        comments.set_kind(0x1002, CommentKind.REPEATABLE)
        comments.clear()
        assert not comments.kinds

    def test_function_and_inline_comments(self):
        proj = self._project()
        comments = proj.kb.comments
        comments[0x1000] = "header"
        comments[0x1002] = "inline"

        assert comments.function_comment(0x1000) == "header"
        assert comments.inline_comment(0x1000) is None
        assert comments.function_comment(0x1002) is None
        assert comments.inline_comment(0x1002) == "inline"

        # explicit PLAIN at the entry renders inline instead of as a header
        comments.set_kind(0x1000, CommentKind.PLAIN)
        assert comments.function_comment(0x1000) is None
        assert comments.inline_comment(0x1000) == "header"

    def test_repeatable_comments(self):
        proj = self._project()
        comments = proj.kb.comments
        comments[0x1002] = "shared buffer"
        comments.set_kind(0x1002, CommentKind.REPEATABLE)

        proj.kb.xrefs.add_xref(XRef(ins_addr=0x2000, dst=0x1002, xref_type=XRefType.Offset))
        assert comments.repeatable_comments_at(0x2000) == [(0x1002, "shared buffer")]
        assert comments.repeatable_comments_at(0x3000) == []

        # editing the comment text keeps it repeatable
        comments[0x1002] = "renamed"
        assert comments.repeatable_comments_at(0x2000) == [(0x1002, "renamed")]

        del comments[0x1002]
        assert comments.repeatable_comments_at(0x2000) == []

    def test_iter_comments(self):
        proj = self._project()
        comments = proj.kb.comments
        comments[0x1002] = "in function"
        comments[0x1000] = "entry"
        comments[0x9000] = "orphan"

        listed = list(comments.iter_comments())
        assert [c.addr for c in listed] == [0x1000, 0x1002, 0x9000]
        assert listed[0].kind == CommentKind.FUNCTION
        assert listed[1].func_addr == 0x1000
        assert listed[2].func_addr is None

    def test_copy_preserves_kinds(self):
        proj = self._project()
        comments = proj.kb.comments
        comments[0x1002] = "c"
        comments.set_kind(0x1002, CommentKind.REPEATABLE)

        clone = comments.copy()
        assert clone[0x1002] == "c"
        assert clone.kind_of(0x1002) == CommentKind.REPEATABLE
        clone.set_kind(0x1002, None)
        assert comments.kind_of(0x1002) == CommentKind.REPEATABLE


if __name__ == "__main__":
    unittest.main()
