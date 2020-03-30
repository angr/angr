
from ...knowledge_base import KnowledgeBase
from ..models import DbKnowledgeBase
from .cfg_model import CFGModelSerializer
from .funcs import FunctionManagerSerializer


class KnowledgeBaseSerializer:
    """
    Serialize/unserialize a KnowledgeBase object.
    """

    @staticmethod
    def dump(session, kb):
        """

        :param session:             The database session object.
        :param KnowledgeBase kb:    The KnowledgeBase instance to serialize.
        :return:                    None
        """

        db_kb = session.query(DbKnowledgeBase).filter_by(name=kb.name).scalar()
        if db_kb is None:
            db_kb = DbKnowledgeBase(name=kb.name)
            session.add(db_kb)

        # dump other stuff
        if 'CFGFast' in kb.cfgs:
            cfg_model = kb.cfgs['CFGFast']
            if cfg_model is not None:
                CFGModelSerializer.dump(session, db_kb, 'CFGFast', cfg_model)

        FunctionManagerSerializer.dump(session, db_kb, kb.functions)

    @staticmethod
    def load(session, project, name):
        """

        :param session:
        :return:
        """

        db_kb = session.query(DbKnowledgeBase).filter_by(name=name).scalar()
        if db_kb is None:
            return None

        kb = KnowledgeBase(project, name=name)

        # Load CFGs
        cfg_model = CFGModelSerializer.load(session, db_kb, 'CFGFast', kb.cfgs)
        if cfg_model is not None:
            kb.cfgs['CFGFast'] = cfg_model

        # Load functions
        funcs = FunctionManagerSerializer.load(session, db_kb, kb)
        if funcs is not None:
            kb.functions = funcs

        return kb
