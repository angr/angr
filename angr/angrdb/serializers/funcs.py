from __future__ import annotations

import json
from typing import TYPE_CHECKING

from sqlalchemy import insert

from angr.angrdb.models import DbFunction
from angr.knowledge_plugins import Function, FunctionManager
from angr.knowledge_plugins.functions.function_manager import SpillingFunctionDict
from angr.protos import function_pb2

if TYPE_CHECKING:
    import networkx

    from angr.angrdb.models import DbKnowledgeBase
    from angr.knowledge_base import KnowledgeBase
    from angr.knowledge_plugins.cfg import CFGModel


class FunctionManagerSerializer:
    """
    Serialize/unserialize a function manager and its functions.
    """

    @staticmethod
    def dump(session, db_kb: DbKnowledgeBase, func_manager: FunctionManager):
        """

        :param session:
        :param DbKnowledgeBase db_kb:
        :param FunctionManager func_manager:
        :return:
        """

        # remove all existing functions
        session.query(DbFunction).filter_by(kb=db_kb).delete()

        # make sure db_kb has a primary key so it can be used as a foreign key in the Core bulk insert below
        session.flush()
        assert db_kb.id is not None

        function_map = func_manager._function_map
        if isinstance(function_map, SpillingFunctionDict):
            # Fast path: copy the serialized bytes of spilled and clean functions directly out of the LMDB backing
            # store (they are guaranteed to be current; see SpillingFunctionDict.export_serialized) instead of
            # deserializing and re-serializing every function. Dirty functions are serialized normally.
            rows = [
                {"kb_id": db_kb.id, "addr": addr, "blob": blob}
                for addr, blob, _copied in function_map.export_serialized()
            ]
        else:
            rows = [{"kb_id": db_kb.id, "addr": func.addr, "blob": func.serialize()} for func in func_manager.values()]

        # bulk-insert the function rows via Core to avoid the per-row ORM unit-of-work overhead
        if rows:
            session.execute(insert(DbFunction), rows)

    @staticmethod
    def load(
        session,
        db_kb: DbKnowledgeBase,
        kb: KnowledgeBase,
        callgraph: networkx.MultiDiGraph | None = None,
        cfg_model: CFGModel | None = None,
    ):
        """

        :param session:
        :param DbKnowledgeBase db_kb:
        :param KnowledgeBase kb:
        :param callgraph:               A deserialized callgraph (if the database stores one). When provided, it is
                                        used directly and the (much slower) callgraph rebuilding logic is skipped.
        :param cfg_model:               An optional CFG model. When provided, the function_address member of all CFG
                                        nodes that belong to a function will be set accordingly.
        :return:                        A loaded function manager.
        """

        funcs: FunctionManager = FunctionManager(kb)

        db_funcs = session.query(DbFunction).filter_by(kb=db_kb)

        function_map = funcs._function_map
        if (
            isinstance(function_map, SpillingFunctionDict)
            and function_map.rtdb is not None
            and function_map.cache_limit is not None
            and db_funcs.count() > function_map.cache_limit
        ):
            # Fast path: there are more functions than the function manager may keep in memory. Move the serialized
            # function bytes directly into the LMDB backing store (the serialized bytes in the database are in the
            # exact format that SpillingFunctionDict spills to LMDB) and register all functions as spilled, instead
            # of deserializing every function and thrashing the LRU cache. Functions are then deserialized on-demand
            # upon first access.
            FunctionManagerSerializer._load_spilled(db_funcs, funcs, function_map, kb._project, cfg_model)
        else:
            for db_func in db_funcs:
                func = Function.parse(db_func.blob, function_manager=funcs, project=kb._project)
                # Mark as dirty so SpillingFunctionDict will save it to LMDB upon eviction.
                func.mark_dirty()
                funcs[func.addr] = func
                if cfg_model is not None:
                    FunctionManagerSerializer._set_cfg_node_function_addresses(
                        cfg_model, func.addr, func.block_addrs_set
                    )

        if callgraph is not None:
            funcs.callgraph = callgraph
        else:
            funcs.rebuild_callgraph()

        return funcs

    @staticmethod
    def _load_spilled(db_funcs, funcs: FunctionManager, function_map: SpillingFunctionDict, project, cfg_model) -> None:
        """
        Move serialized functions directly into the LMDB backing store of the given SpillingFunctionDict without
        deserializing them, and populate the caches of the function manager that are normally populated when a
        function is added to the manager.
        """

        items: list[tuple[int, bytes]] = []

        for db_func in db_funcs:
            addr = db_func.addr
            blob = db_func.blob
            items.append((addr, blob))

            cmsg = function_pb2.Function()  # type: ignore  # pylint:disable=no-member
            cmsg.ParseFromString(blob)

            # populate the function manager caches; this mirrors what FunctionManager._function_added() does when a
            # deserialized function is inserted into the function manager
            funcs.function_addrs_set.add(addr)
            funcs.callgraph.add_node(addr)

            returning = cmsg.returning if cmsg.HasField("returning") else None
            if returning is None and project is not None:
                returning = FunctionManagerSerializer._get_initial_returning(
                    project, addr, cmsg.is_syscall, cmsg.is_simprocedure
                )
            funcs.set_function_returning(addr, returning)

            block_addrs = {b.ea for b in cmsg.blocks}
            funcs.set_func_block_count(addr, len(block_addrs))

            funcs._func_name_to_addrs[cmsg.name].add(addr)

            if cmsg.info:
                info = json.loads(cmsg.info.decode("utf-8"))
                for key, value in info.items():
                    if key.startswith("is_") and value is True:
                        funcs.add_key_func_addr(key[3:], addr)

            if cfg_model is not None:
                FunctionManagerSerializer._set_cfg_node_function_addresses(cfg_model, addr, block_addrs)

        function_map.bulk_import_serialized(items)

    @staticmethod
    def _set_cfg_node_function_addresses(cfg_model, func_addr: int, block_addrs) -> None:
        for block_addr in block_addrs:
            node = cfg_model.get_any_node(block_addr)
            if node is not None:
                node.function_address = func_addr

    @staticmethod
    def _get_initial_returning(project, addr: int, is_syscall: bool, is_simprocedure: bool) -> bool | None:
        """
        Determine the returning status of a hooked function. This mirrors Function._get_initial_returning(), which is
        invoked by the Function constructor when the "returning" status of a function is unknown.
        """

        hooker = None
        if is_syscall:
            hooker = project.simos.syscall_from_addr(addr)
        elif is_simprocedure:
            hooker = project.hooked_by(addr)
        if hooker:
            if getattr(hooker, "DYNAMIC_RET", False):
                return True
            return hooker.returns
        return None
