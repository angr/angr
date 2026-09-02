from __future__ import annotations

from angr.angrdb.models import DbBookmark
from angr.knowledge_plugins.bookmarks import Bookmark, Bookmarks


class BookmarksSerializer:
    """
    Serialize/unserialize bookmarks to/from a database session.
    """

    @staticmethod
    def dump(session, db_kb, bookmarks):
        """

        :param session:
        :param DbKnowledgeBase db_kb:
        :param Bookmarks bookmarks:
        :return:                        None
        """

        # bookmark lists are small; rewrite them wholesale so removals persist
        for db_bookmark in list(db_kb.bookmarks):
            session.delete(db_bookmark)
        for bookmark in bookmarks:
            session.add(
                DbBookmark(
                    kb=db_kb,
                    addr=bookmark.addr,
                    label=bookmark.label,
                    created_at=bookmark.created_at,
                )
            )

    @staticmethod
    def load(session, db_kb, kb):  # pylint:disable=unused-argument
        """

        :param session:
        :param DbKnowledgeBase db_kb:
        :param KnowledgeBase kb:
        :return:
        """

        bookmarks = Bookmarks(kb)
        for db_bookmark in db_kb.bookmarks:
            bookmarks.append(Bookmark(db_bookmark.addr, db_bookmark.label or "", db_bookmark.created_at))
        return bookmarks
