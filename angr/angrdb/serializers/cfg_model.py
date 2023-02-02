# pylint:disable=unused-import
from ..models import DbCFGModel
from ...knowledge_plugins.cfg.cfg_model import CFGModel


class CFGModelSerializer:
    """
    Serialize/unserialize a CFGModel.
    """

    @staticmethod
    def dump(session, db_kb, ident, cfg_model):
        """

        :param session:
        :param DbKnowledgeBase db_kb:   The database object for KnowledgeBase.
        :param str ident:               Identifier of the CFG model.
        :param CFGModel cfg_model:      The CFG model to dump.
        :return:                        None
        """

        db_cfg_id = session.query(DbCFGModel.id).filter_by(ident=ident).scalar()
        if db_cfg_id is not None:
            # remove the existing CFG
            session.query(DbCFGModel).filter_by(id=db_cfg_id).delete()

        db_cfg = DbCFGModel(
            kb=db_kb,
            ident=ident,
            blob=cfg_model.serialize(),
        )
        session.add(db_cfg)

    @staticmethod
    def load(session, db_kb, ident, cfg_manager, loader=None):
        db_cfg: DbCFGModel = session.query(DbCFGModel).filter_by(kb=db_kb, ident=ident).scalar()
        if db_cfg is None:
            return None

        cfg_model = CFGModel.parse(db_cfg.blob, cfg_manager=cfg_manager, loader=loader)
        return cfg_model
