# pylint:disable=unused-import
from ...knowledge_base import KnowledgeBase
from ...knowledge_plugins import FunctionManager, Function
from ..models import DbFunction, DbKnowledgeBase


class FunctionManagerSerializer:
    """
    Serialize/unserialize a function manager and its functions.
    """

    @staticmethod
    def dump(session, db_kb, func_manager):
        """

        :param session:
        :param DbKnowledgeBase db_kb:
        :param FunctionManager func_manager:
        :return:
        """

        # remove all existing functions
        session.query(DbFunction).filter_by(kb=db_kb).delete()

        for func in func_manager.values():
            db_func = DbFunction(
                kb=db_kb,
                addr=func.addr,
                blob=func.serialize(),
            )
            session.add(db_func)

    @staticmethod
    def load(session, db_kb, kb):
        """

        :param session:
        :param DbKnowledgeBase db_kb:
        :param KnowledgeBase kb:
        :return:                        A loaded function manager.
        """

        funcs = FunctionManager(kb)

        db_funcs = session.query(DbFunction).filter_by(kb=db_kb)
        all_func_addrs = set(map(lambda x: x[0], session.query(DbFunction.addr).filter_by(kb=db_kb)))

        for db_func in db_funcs:
            func = Function.parse(db_func.blob, function_manager=funcs, project=kb._project,
                                  all_func_addrs=all_func_addrs)
            funcs[func.addr] = func

        return funcs
