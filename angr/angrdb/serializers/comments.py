# pylint:disable=unused-import
from __future__ import annotations
from ..models import DbComment
from ...knowledge_plugins.comments import Comments


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

        for addr, comment in comments.items():
            db_comment = (
                session.query(DbComment)
                .filter_by(
                    kb=db_kb,
                    addr=addr,
                )
                .scalar()
            )
            if db_comment is not None:
                if comment == db_comment.comment:
                    continue
                db_comment.comment = comment
            else:
                db_comment = DbComment(
                    kb=db_kb,
                    addr=addr,
                    comment=comment,
                    type=0,
                )
                session.add(db_comment)

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

        return comments
