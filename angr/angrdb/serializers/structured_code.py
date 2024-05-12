from typing import Any, TYPE_CHECKING
import json
import pickle

from ...analyses.decompiler.structured_codegen import DummyStructuredCodeGenerator
from ...analyses.decompiler.decompilation_cache import DecompilationCache
from ...knowledge_plugins import StructuredCodeManager
from ..models import DbStructuredCode

if TYPE_CHECKING:
    from angr.knowledge_base import KnowledgeBase
    from angr.angrdb.models import DbKnowledgeBase


class StructuredCodeManagerSerializer:
    """
    Serialize/unserialize a structured code manager.
    """

    @staticmethod
    def dump(session, db_kb: "DbKnowledgeBase", code_manager: StructuredCodeManager):
        """

        :param session:
        :param db_kb:
        :param code_manager:
        :return:
        """

        # remove all existing stored structured code
        session.query(DbStructuredCode).filter_by(kb=db_kb).delete()

        for key, cache in code_manager.cached.items():
            func_addr, flavor = key

            # TODO: Cache types

            expr_comments = None
            if cache.codegen.expr_comments:
                expr_comments = json.dumps(cache.codegen.expr_comments).encode("utf-8")

            stmt_comments = None
            if cache.codegen.stmt_comments:
                stmt_comments = json.dumps(cache.codegen.stmt_comments).encode("utf-8")

            const_formats = None
            if cache.codegen.const_formats:
                const_formats = pickle.dumps(cache.codegen.const_formats)

            ite_exprs = None
            if cache.ite_exprs:
                ite_exprs = pickle.dumps(cache.ite_exprs)

            db_code = DbStructuredCode(
                kb=db_kb,
                func_addr=func_addr,
                flavor=flavor,
                expr_comments=expr_comments,
                stmt_comments=stmt_comments,
                const_formats=const_formats,
                ite_exprs=ite_exprs,
                # configuration=configuration,
            )
            session.add(db_code)

    @staticmethod
    def dict_strkey_to_intkey(d: dict[str, Any]) -> dict[int, Any]:
        new_d = {}

        for key, value in d.items():
            try:
                new_d[int(key)] = value
            except (ValueError, TypeError):
                continue

        return new_d

    @staticmethod
    def load(session, db_kb: "DbKnowledgeBase", kb: "KnowledgeBase") -> StructuredCodeManager:
        """

        :param session:
        :param db_kb:
        :param kb:
        :return:                        A loaded structured code manager
        """

        manager = StructuredCodeManager(kb)

        db_code_collection = session.query(DbStructuredCode).filter_by(kb=db_kb)

        for db_code in db_code_collection:
            if not db_code.expr_comments:
                expr_comments = None
            else:
                expr_comments = json.loads(db_code.expr_comments.decode("utf-8"))
                expr_comments = StructuredCodeManagerSerializer.dict_strkey_to_intkey(expr_comments)

            if not db_code.stmt_comments:
                stmt_comments = None
            else:
                stmt_comments = json.loads(db_code.stmt_comments.decode("utf-8"))
                stmt_comments = StructuredCodeManagerSerializer.dict_strkey_to_intkey(stmt_comments)

            if not db_code.const_formats:
                const_formats = None
            else:
                const_formats = pickle.loads(db_code.const_formats)

            if not db_code.ite_exprs:
                ite_exprs = None
            else:
                ite_exprs = pickle.loads(db_code.ite_exprs)

            configuration = None
            dummy_codegen = DummyStructuredCodeGenerator(
                db_code.flavor,
                expr_comments=expr_comments,
                stmt_comments=stmt_comments,
                configuration=configuration,
                const_formats=const_formats,
            )
            cache = DecompilationCache(db_code.func_addr)
            cache.codegen = dummy_codegen
            cache.ite_exprs = ite_exprs
            manager[(db_code.func_addr, db_code.flavor)] = cache

        return manager
