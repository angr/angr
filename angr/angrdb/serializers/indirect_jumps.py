from __future__ import annotations

from angr.knowledge_plugins.indirect_jumps import IndirectJumps

from .plugin_data import PluginDataStore

PLUGIN = "indirect_jumps"


class IndirectJumpsSerializer:
    """
    Serialize/unserialize resolved and unresolved indirect jumps to/from a database session.
    """

    @staticmethod
    def dump(session, db_kb, indirect_jumps: IndirectJumps):
        data = {
            "unresolved": sorted(indirect_jumps.unresolved),
            "resolved": {str(addr): list(targets) for addr, targets in indirect_jumps.resolved.items()},
        }
        PluginDataStore.save(session, db_kb, PLUGIN, data)

    @staticmethod
    def load(session, db_kb, kb) -> IndirectJumps:
        indirect_jumps = IndirectJumps(kb)
        data = PluginDataStore.load(session, db_kb, PLUGIN)
        if data is not None:
            indirect_jumps.unresolved = set(data["unresolved"])
            indirect_jumps.resolved = {int(addr): targets for addr, targets in data["resolved"].items()}
        return indirect_jumps
