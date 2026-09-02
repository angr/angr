from __future__ import annotations

import time

from .plugin import KnowledgeBasePlugin


class Bookmark:
    """
    A user-marked address with an optional label.
    """

    __slots__ = ("addr", "created_at", "label")

    def __init__(self, addr: int, label: str = "", created_at: float | None = None) -> None:
        self.addr = addr
        self.label = label
        self.created_at = time.time() if created_at is None else created_at

    def __repr__(self) -> str:
        return f"<Bookmark {self.addr:#x} {self.label!r}>"


class Bookmarks(KnowledgeBasePlugin, list):
    """
    Tracks bookmarks as a list of :class:`Bookmark`, in creation order.
    """

    def copy(self):
        o = Bookmarks(self._kb)
        o.extend(self)
        return o

    def get_bookmark(self, addr: int) -> Bookmark | None:
        for bookmark in self:
            if bookmark.addr == addr:
                return bookmark
        return None

    def has_bookmark(self, addr: int) -> bool:
        return self.get_bookmark(addr) is not None

    def add_bookmark(self, addr: int, label: str = "") -> tuple[Bookmark, bool]:
        """
        Bookmark ``addr``, or relabel the bookmark already there if ``label`` is non-empty.
        Returns the bookmark and whether it was newly created.
        """
        existing = self.get_bookmark(addr)
        if existing is not None:
            if label:
                existing.label = label
            return existing, False
        bookmark = Bookmark(addr, label)
        self.append(bookmark)
        return bookmark, True

    def remove_bookmark(self, bookmark: Bookmark) -> bool:
        """Remove ``bookmark`` if present. Returns whether it was removed."""
        if bookmark in self:
            self.remove(bookmark)
            return True
        return False

    def toggle_bookmark(self, addr: int, label: str = "") -> Bookmark | None:
        """Add a bookmark at ``addr``, or remove the one already there. Returns the new one, if any."""
        existing = self.get_bookmark(addr)
        if existing is None:
            return self.add_bookmark(addr, label)[0]
        self.remove(existing)
        return None

    def sorted_bookmarks(self) -> list[Bookmark]:
        return sorted(self, key=lambda b: b.addr)

    def next_bookmark(self, after_addr: int | None) -> Bookmark | None:
        """The next bookmark by address, wrapping around."""
        ordered = self.sorted_bookmarks()
        if not ordered:
            return None
        if after_addr is None:
            return ordered[0]
        for bookmark in ordered:
            if bookmark.addr > after_addr:
                return bookmark
        return ordered[0]


KnowledgeBasePlugin.register_default("bookmarks", Bookmarks)
