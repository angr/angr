# pylint:disable=unused-import
from __future__ import annotations

from angr.angrdb.models import DbComment
from angr.knowledge_plugins.comments import CommentKind, Comments


class CommentsSerializer:
    """
    Serialize/unserialize comments to/from a database session.
    """

    @staticmethod
    def dump(session, db_kb, comments):
        """

        :param session:
        :param DbKnowledgeBase db_kb:
        :param Comments comments:
        :return:                        None
        """

        existing = {db_comment.addr: db_comment for db_comment in session.query(DbComment).filter_by(kb=db_kb)}
        for addr, comment in comments.items():
            # type: 0 = no explicit kind, otherwise CommentKind + 1; an explicit PLAIN (e.g. at a
            # function entry, overriding the FUNCTION default) must survive the round trip
            kind = comments.kinds.get(addr)
            db_type = 0 if kind is None else int(kind) + 1
            db_comment = existing.pop(addr, None)
            if db_comment is not None:
                if comment == db_comment.comment and db_type == (db_comment.type or 0):
                    continue
                db_comment.comment = comment
                db_comment.type = db_type
            else:
                db_comment = DbComment(
                    kb=db_kb,
                    addr=addr,
                    comment=comment,
                    type=db_type,
                )
                session.add(db_comment)

        # comments removed from the knowledge base must not resurrect on the next load
        for db_comment in existing.values():
            session.delete(db_comment)

    @staticmethod
    def load(session, db_kb, kb):  # pylint:disable=unused-argument
        """

        :param session:
        :param DbKnowledgeBase db_kb:
        :param KnowledgeBase kb:
        :return:
        """

        db_comments = db_kb.comments
        comments = Comments(kb)

        for db_comment in db_comments:
            comments[db_comment.addr] = db_comment.comment
            if db_comment.type:
                # assign directly: set_kind()'s normalization needs kb.functions, which may not be
                # loaded into this kb yet
                comments.kinds[db_comment.addr] = CommentKind(db_comment.type - 1)

        return comments
