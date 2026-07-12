from __future__ import annotations

from typing import TYPE_CHECKING

from sqlalchemy import insert

from angr.angrdb.models import DbVariableCollection
from angr.knowledge_plugins import VariableManager
from angr.knowledge_plugins.variables.variable_manager import VariableManagerInternal

if TYPE_CHECKING:
    from angr.angrdb.models import DbKnowledgeBase
    from angr.knowledge_base import KnowledgeBase


class VariableManagerSerializer:
    """
    Serialize/unserialize a variable manager and its variables.
    """

    @staticmethod
    def dump(session, db_kb: DbKnowledgeBase, var_manager: VariableManager):
        # Remove all existing variable collections
        session.query(DbVariableCollection).filter_by(kb=db_kb).delete()

        # make sure db_kb has a primary key so it can be used as a foreign key in the Core bulk insert below
        session.flush()
        assert db_kb.id is not None

        # Dump all variable manager internal instances
        rows = []
        for func_addr, internal in var_manager.function_managers.items():
            row = VariableManagerSerializer._internal_row(db_kb, internal, func_addr, ident=None)
            if row is not None:
                rows.append(row)
        # dump the global variable manager internal
        global_row = VariableManagerSerializer._internal_row(db_kb, var_manager.global_manager, -1, ident=None)
        if global_row is not None:
            rows.append(global_row)

        # bulk-insert the variable collection rows via Core to avoid the per-row ORM unit-of-work overhead
        if rows:
            session.execute(insert(DbVariableCollection), rows)

    @staticmethod
    def _internal_row(
        db_kb: DbKnowledgeBase, internal_manager: VariableManagerInternal, func_addr: int, ident=None
    ) -> dict | None:
        blob = internal_manager.serialize()
        if not blob:
            # the variable manager is empty: it serializes to a zero-length protobuf message, which by proto3
            # semantics happens exactly when it holds no variables, no phi variables, no variable accesses, no
            # unified variables, and no relations. Empty variable managers are not stored.
            return None

        return {"kb_id": db_kb.id, "ident": ident or None, "func_addr": func_addr, "blob": blob}

    @staticmethod
    def load(session, db_kb: DbKnowledgeBase, kb: KnowledgeBase, ident=None):
        variable_manager = VariableManager(kb)

        db_varcolls = session.query(DbVariableCollection).filter_by(kb=db_kb, ident=ident)
        for db_varcoll in db_varcolls:
            if not db_varcoll.blob:
                # databases created by older versions of angr may contain empty variable managers; they decode to
                # managers without any content and are re-created on demand, so they are not loaded
                continue
            internal = VariableManagerSerializer.load_internal(db_varcoll, variable_manager)
            if internal.func_addr is None:
                variable_manager.global_manager = internal
            else:
                variable_manager.function_managers[internal.func_addr] = internal

        return variable_manager

    @staticmethod
    def load_internal(db_varcoll, variable_manager: VariableManager) -> VariableManagerInternal:
        return VariableManagerInternal.parse(
            db_varcoll.blob,
            variable_manager=variable_manager,
            func_addr=db_varcoll.func_addr if db_varcoll.func_addr != -1 else None,
        )
