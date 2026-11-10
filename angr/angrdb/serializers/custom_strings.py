from __future__ import annotations

from angr.knowledge_plugins.custom_strings import CustomStrings

from .plugin_data import PluginDataStore

PLUGIN = "custom_strings"


class CustomStringsSerializer:
    """
    Serialize/unserialize custom strings to/from a database session.
    """

    @staticmethod
    def dump(session, db_kb, custom_strings: CustomStrings):
        data = {
            "string_id": custom_strings.string_id,
            "strings": PluginDataStore.bytes_map_to_json(custom_strings.strings),
        }
        PluginDataStore.save(session, db_kb, PLUGIN, data)

    @staticmethod
    def load(session, db_kb, kb) -> CustomStrings:
        custom_strings = CustomStrings(kb)
        data = PluginDataStore.load(session, db_kb, PLUGIN)
        if data is not None:
            custom_strings.string_id = data["string_id"]
            custom_strings.strings = PluginDataStore.bytes_map_from_json(data["strings"])
        return custom_strings
