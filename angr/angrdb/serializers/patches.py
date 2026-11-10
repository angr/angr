from __future__ import annotations

from angr.knowledge_plugins.patches import PatchManager

from .plugin_data import PluginDataStore

PLUGIN = "patches"


class PatchesSerializer:
    """
    Serialize/unserialize binary patches to/from a database session.
    """

    @staticmethod
    def dump(session, db_kb, patches: PatchManager):
        data = {
            "patches": [
                {"addr": patch.addr, "bytes": bytes(patch.new_bytes).hex(), "comment": patch.comment}
                for patch in patches.values()
            ]
        }
        PluginDataStore.save(session, db_kb, PLUGIN, data)

    @staticmethod
    def load(session, db_kb, kb) -> PatchManager:
        patches = PatchManager(kb)
        data = PluginDataStore.load(session, db_kb, PLUGIN)
        if data is not None:
            for patch in data["patches"]:
                patches.add_patch(patch["addr"], bytes.fromhex(patch["bytes"]), comment=patch["comment"])
        return patches
