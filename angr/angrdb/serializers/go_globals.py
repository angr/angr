# pylint:disable=protected-access
from __future__ import annotations

from angr.go.knowledge_plugins.go_globals import GoGlobals
from angr.go.signature import GoVariable

from .plugin_data import PluginDataStore

PLUGIN = "go_globals"


class GoGlobalsSerializer:
    """
    Serialize/unserialize recovered Go package-level variables to/from a database session.
    """

    @staticmethod
    def dump(session, db_kb, go_globals: GoGlobals):
        data = {
            "loaded": go_globals.loaded,
            "variables": [[var.name, var.addr, var.type_str] for var in go_globals._by_addr.values()],
        }
        PluginDataStore.save(session, db_kb, PLUGIN, data)

    @staticmethod
    def load(session, db_kb, kb) -> GoGlobals | None:
        """None when the database holds no Go globals: the plugin then stays lazily computed."""
        data = PluginDataStore.load(session, db_kb, PLUGIN)
        if data is None:
            return None
        go_globals = GoGlobals(kb)
        for name, addr, type_str in data["variables"]:
            go_globals.note(GoVariable(name, addr, type_str))
        if data["loaded"]:
            go_globals.mark_loaded()
        return go_globals
