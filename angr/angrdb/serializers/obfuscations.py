from __future__ import annotations

from angr.knowledge_plugins.obfuscations import Obfuscations

from .plugin_data import PluginDataStore

PLUGIN = "obfuscations"


class ObfuscationsSerializer:
    """
    Serialize/unserialize obfuscation findings to/from a database session.
    """

    @staticmethod
    def dump(session, db_kb, obfuscations: Obfuscations):
        to_json = PluginDataStore.bytes_map_to_json
        data = {
            "strings_analyzed": obfuscations.obfuscated_strings_analyzed,
            "type1_strings": to_json(obfuscations.type1_deobfuscated_strings),
            "type1_string_loaders": sorted(obfuscations.type1_string_loader_candidates),
            "type2_strings": to_json(obfuscations.type2_deobfuscated_strings),
            "type2_string_loaders": sorted(obfuscations.type2_string_loader_candidates),
            "type3_strings": to_json(obfuscations.type3_deobfuscated_strings),
            "apis_analyzed": obfuscations.obfuscated_apis_analyzed,
            "type1_apis": {str(k): list(v) for k, v in obfuscations.type1_deobfuscated_apis.items()},
            "type2_apis": {str(k): v for k, v in obfuscations.type2_deobfuscated_apis.items()},
            "type3_apis": {str(k): list(v) for k, v in obfuscations.type3_deobfuscated_apis.items()},
        }
        PluginDataStore.save(session, db_kb, PLUGIN, data)

    @staticmethod
    def load(session, db_kb, kb) -> Obfuscations:
        obfuscations = Obfuscations(kb)
        data = PluginDataStore.load(session, db_kb, PLUGIN)
        if data is None:
            return obfuscations
        from_json = PluginDataStore.bytes_map_from_json
        obfuscations.obfuscated_strings_analyzed = data["strings_analyzed"]
        obfuscations.type1_deobfuscated_strings = from_json(data["type1_strings"])
        obfuscations.type1_string_loader_candidates = set(data["type1_string_loaders"])
        obfuscations.type2_deobfuscated_strings = from_json(data["type2_strings"])
        obfuscations.type2_string_loader_candidates = set(data["type2_string_loaders"])
        obfuscations.type3_deobfuscated_strings = from_json(data["type3_strings"])
        obfuscations.obfuscated_apis_analyzed = data["apis_analyzed"]
        obfuscations.type1_deobfuscated_apis = {int(k): (v[0], v[1]) for k, v in data["type1_apis"].items()}
        obfuscations.type2_deobfuscated_apis = {int(k): v for k, v in data["type2_apis"].items()}
        obfuscations.type3_deobfuscated_apis = {int(k): (v[0], v[1]) for k, v in data["type3_apis"].items()}
        return obfuscations
