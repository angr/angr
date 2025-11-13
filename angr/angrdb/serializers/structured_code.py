from __future__ import annotations
from typing import Any, TYPE_CHECKING
import json

from angr.analyses.decompiler.structured_codegen import DummyStructuredCodeGenerator
from angr.analyses.decompiler.structured_codegen.base import CConstantType
from angr.analyses.decompiler.decompilation_cache import DecompilationCache
from angr.knowledge_plugins import StructuredCodeManager
from angr.angrdb.models import DbStructuredCode

if TYPE_CHECKING:
    from angr.analyses.decompiler.structured_codegen.base import IdentType
    from angr.knowledge_base import KnowledgeBase
    from angr.angrdb.models import DbKnowledgeBase


class ConstFormatsSerializer:
    """
    Serialize/deserialize the constant formats dictionary.
    """

    @staticmethod
    def to_json(const_formats: dict[IdentType, dict[str, bool]]) -> dict[int, dict[str, dict[str, bool]]]:
        d = {}
        for key, value in const_formats.items():
            ins_addr, v_type, v = key
            v_type_str = (
                "i" if v_type == CConstantType.INT.value else "f" if v_type == CConstantType.FLOAT.value else "s"
            )  # str
            if ins_addr not in d:
                d[ins_addr] = {}
            d_key = f"{v_type_str}{v}"
            d[ins_addr][d_key] = value
        return d

    @staticmethod
    def from_json(data: dict[int, dict[str, dict[str, str | bool]]]) -> dict[IdentType, dict[str, bool]]:
        r = {}
        for ins_addr, d_ in data.items():
            for d_key, d in d_.items():
                ch = d_key[0]
                if ch == "i":
                    v_type = CConstantType.INT.value
                    value = int(d_key[1:])
                elif ch == "f":
                    v_type = CConstantType.FLOAT.value
                    value = float(d_key[1:])
                else:  # ch == "s"
                    v_type = CConstantType.STRING.value
                    value = d_key[1:]
                key_tpl: IdentType = int(ins_addr), v_type, value
                r[key_tpl] = {}
                for k, v in d.items():
                    r[key_tpl][k] = v is True or (isinstance(v, str) and v.lower() == "true")
        return r


class StructuredCodeManagerSerializer:
    """
    Serialize/deserialize a structured code manager.
    """

    @staticmethod
    def dump(session, db_kb: DbKnowledgeBase, code_manager: StructuredCodeManager):
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
            if cache.codegen is not None and cache.codegen.expr_comments:
                expr_comments = json.dumps(cache.codegen.expr_comments).encode("utf-8")

            stmt_comments = None
            if cache.codegen is not None and cache.codegen.stmt_comments:
                stmt_comments = json.dumps(cache.codegen.stmt_comments).encode("utf-8")

            const_formats = None
            if cache.codegen is not None and cache.codegen.const_formats:
                const_formats = json.dumps(ConstFormatsSerializer.to_json(cache.codegen.const_formats)).encode("utf-8")

            ite_exprs = None

            db_code = DbStructuredCode(
                kb=db_kb,
                func_addr=func_addr,
                flavor=flavor,
                expr_comments=expr_comments,
                stmt_comments=stmt_comments,
                const_formats=const_formats,
                ite_exprs=ite_exprs,
                errors="\n\n\n".join(cache.errors),
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
    def load(session, db_kb: DbKnowledgeBase, kb: KnowledgeBase) -> StructuredCodeManager:
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

            const_formats = (
                None
                if not db_code.const_formats
                else ConstFormatsSerializer.from_json(json.loads(db_code.const_formats.decode("utf-8")))
            )

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
            cache.ite_exprs = set()
            cache.errors = db_code.errors.split("\n\n\n")
            manager[(db_code.func_addr, db_code.flavor)] = cache

        return manager
