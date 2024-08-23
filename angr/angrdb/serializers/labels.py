# pylint:disable=unused-import
from __future__ import annotations
from ..models import DbLabel
from ...knowledge_plugins.labels import Labels


class LabelsSerializer:
    """
    Serialize/unserialize labels to/from a database session.
    """

    @staticmethod
    def dump(session, db_kb, labels):
        """

        :param session:
        :param DbKnowledgeBase db_kb:
        :param Labels labels:
        :return:                        None
        """

        for addr, name in labels.items():
            db_label = (
                session.query(DbLabel)
                .filter_by(
                    kb=db_kb,
                    addr=addr,
                )
                .scalar()
            )
            if db_label is not None:
                if name == db_label.name:
                    continue
                db_label.name = name
            else:
                db_label = DbLabel(
                    kb=db_kb,
                    addr=addr,
                    name=name,
                )
                session.add(db_label)

    @staticmethod
    def load(session, db_kb, kb):  # pylint:disable=unused-argument
        """

        :param session:
        :param DbKnowledgeBase db_kb:
        :param KnowledgeBase kb:
        :return:
        """

        db_labels = db_kb.labels
        labels = Labels(kb)

        for db_label in db_labels:
            labels[db_label.addr] = db_label.name

        return labels
