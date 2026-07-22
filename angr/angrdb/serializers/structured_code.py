from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from sqlalchemy import insert

from angr.analyses.decompiler.decompilation_cache import DecompilationCache
from angr.analyses.decompiler.structured_codegen import DummyStructuredCodeGenerator
from angr.analyses.decompiler.structured_codegen.base import CConstantType
from angr.angrdb.models import DbDecompilationCache, DbStructuredCode
from angr.knowledge_plugins import StructuredCodeManager
from angr.knowledge_plugins.structured_code import CacheKey, SpillingDecompilationDict

if TYPE_CHECKING:
    from angr.analyses.decompiler.structured_codegen.base import IdentType
    from angr.angrdb.models import DbKnowledgeBase
    from angr.knowledge_base import KnowledgeBase


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
                key_tpl: IdentType = int(ins_addr), v_type, str(value)
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
        Store every decompilation cache as its fully serialized protobuf bytes (the ``decompilation_caches`` table).
        Caches that cannot be serialized (e.g. dummy or rust-flavor codegens) fall back to the legacy
        ``structured_code`` rows storing codegen metadata only.

        :param session:
        :param db_kb:
        :param code_manager:
        :return:
        """

        # remove all existing stored structured code
        session.query(DbStructuredCode).filter_by(kb=db_kb).delete()
        session.query(DbDecompilationCache).filter_by(kb=db_kb).delete()

        # make sure db_kb has a primary key so it can be used as a foreign key in the Core bulk insert below
        session.flush()
        assert db_kb.id is not None

        backing = code_manager.cached
        serialized: list[tuple[CacheKey, bytes]]
        unserializable: dict[CacheKey, DecompilationCache]
        if isinstance(backing, SpillingDecompilationDict):
            # copy the serialized bytes of spilled caches directly out of the LMDB backing store instead of
            # deserializing and re-serializing them
            serialized, unserializable = backing.export_serialized()
        else:
            serialized = []
            unserializable = {}
            for key, cache in backing.items():
                try:
                    serialized.append((key, cache.serialize()))
                except Exception:  # pylint:disable=broad-exception-caught
                    unserializable[key] = cache

        rows = [
            {"kb_id": db_kb.id, "func_addr": func_addr, "flavor": flavor, "blob": blob}
            for (func_addr, flavor), blob in serialized
        ]
        # bulk-insert via Core to avoid the per-row ORM unit-of-work overhead
        if rows:
            session.execute(insert(DbDecompilationCache), rows)

        for key, cache in unserializable.items():
            StructuredCodeManagerSerializer._dump_legacy(session, db_kb, key, cache)

    @staticmethod
    def _dump_legacy(session, db_kb: DbKnowledgeBase, key: CacheKey, cache: DecompilationCache) -> None:
        """Store codegen metadata (comments, constant formats, errors) of an unserializable cache."""
        func_addr, flavor = key

        expr_comments = None
        if cache.codegen is not None and cache.codegen.expr_comments:
            expr_comments = json.dumps(cache.codegen.expr_comments).encode("utf-8")

        stmt_comments = None
        if cache.codegen is not None and cache.codegen.stmt_comments:
            stmt_comments = json.dumps(cache.codegen.stmt_comments).encode("utf-8")

        const_formats = None
        if cache.codegen is not None and cache.codegen.const_formats:
            const_formats = json.dumps(ConstFormatsSerializer.to_json(cache.codegen.const_formats)).encode("utf-8")

        db_code = DbStructuredCode(
            kb=db_kb,
            func_addr=func_addr,
            flavor=flavor,
            expr_comments=expr_comments,
            stmt_comments=stmt_comments,
            const_formats=const_formats,
            ite_exprs=None,
            errors="\n\n\n".join(cache.errors),
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
        Load decompilation caches: fully serialized caches from the ``decompilation_caches`` table first, then legacy
        ``structured_code`` rows (from this database or from old databases) for any key not already loaded.

        :param session:
        :param db_kb:
        :param kb:
        :return:                        A loaded structured code manager
        """

        manager = StructuredCodeManager(kb)
        backing = manager.cached

        db_caches = session.query(DbDecompilationCache).filter_by(kb=db_kb)
        if isinstance(backing, SpillingDecompilationDict) and db_caches.count() > backing.cache_limit:
            # move the serialized bytes directly into the LMDB backing store and register every cache as spilled,
            # instead of deserializing every cache and thrashing the LRU cache
            backing.bulk_import_serialized(
                [((db_cache.func_addr, db_cache.flavor), db_cache.blob) for db_cache in db_caches]
            )
        else:
            for db_cache in db_caches:
                cache = DecompilationCache.parse(
                    db_cache.blob,
                    project=kb._project,  # pylint:disable=protected-access
                    kb=kb,
                    function=kb.functions.get(db_cache.func_addr),
                )
                backing[(db_cache.func_addr, db_cache.flavor)] = cache

        db_code_collection = session.query(DbStructuredCode).filter_by(kb=db_kb)

        for db_code in db_code_collection:
            if (db_code.func_addr, db_code.flavor) in backing:
                continue
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
