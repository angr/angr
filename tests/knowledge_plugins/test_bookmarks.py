#!/usr/bin/env python3
# pylint:disable=no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.knowledge_plugins"  # pylint:disable=redefined-builtin

import unittest

import angr


class BookmarksTests(unittest.TestCase):
    """
    Tests for the Bookmarks knowledge plugin.
    """

    def _bookmarks(self):
        proj = angr.load_shellcode(b"\xc3", arch="AMD64", load_address=0x1000)
        return proj.kb.bookmarks

    def test_add_and_relabel(self):
        bookmarks = self._bookmarks()
        first, created = bookmarks.add_bookmark(0x1000, "entry")
        assert created
        assert bookmarks.has_bookmark(0x1000)
        assert bookmarks.get_bookmark(0x1000) is first

        again, created = bookmarks.add_bookmark(0x1000, "renamed")
        assert not created
        assert again is first
        assert first.label == "renamed"

        # an empty label leaves the existing one alone
        bookmarks.add_bookmark(0x1000)
        assert first.label == "renamed"
        assert len(bookmarks) == 1

    def test_toggle_and_remove(self):
        bookmarks = self._bookmarks()
        bookmark = bookmarks.toggle_bookmark(0x1000)
        assert bookmark is not None
        assert bookmarks.toggle_bookmark(0x1000) is None
        assert not bookmarks.has_bookmark(0x1000)

        bookmark, _ = bookmarks.add_bookmark(0x1000)
        assert bookmarks.remove_bookmark(bookmark)
        assert not bookmarks.remove_bookmark(bookmark)

    def test_sorted_and_next(self):
        bookmarks = self._bookmarks()
        bookmarks.add_bookmark(0x3000)
        bookmarks.add_bookmark(0x1000)
        bookmarks.add_bookmark(0x2000)

        assert [b.addr for b in bookmarks.sorted_bookmarks()] == [0x1000, 0x2000, 0x3000]
        # creation order is preserved in the plugin itself
        assert [b.addr for b in bookmarks] == [0x3000, 0x1000, 0x2000]

        assert bookmarks.next_bookmark(None).addr == 0x1000
        assert bookmarks.next_bookmark(0x1000).addr == 0x2000
        assert bookmarks.next_bookmark(0x3000).addr == 0x1000  # wraps around

        assert self._bookmarks().next_bookmark(None) is None

    def test_copy(self):
        bookmarks = self._bookmarks()
        bookmarks.add_bookmark(0x1000, "a")
        clone = bookmarks.copy()
        clone.add_bookmark(0x2000, "b")
        assert len(bookmarks) == 1
        assert len(clone) == 2


if __name__ == "__main__":
    unittest.main()
