# pylint:disable=protected-access
from __future__ import annotations

from typing import Any

from angr.go.knowledge_plugins.go_signatures import GoInferredSignature, GoSignatures

from .plugin_data import PluginDataStore

PLUGIN = "go_signatures"


class GoSignaturesSerializer:
    """
    Serialize/unserialize what Go signature inference recorded (inferred signatures, call-site records, closure
    contexts and their versions) to/from a database session. Signature sources are not stored: they are reloaded
    from the binary and the stdlib database.
    """

    @staticmethod
    def _record_from_json(d: dict[str, Any]) -> GoInferredSignature:
        rec = GoInferredSignature()
        rec.merge(
            d.get("params"),
            d.get("results"),
            d.get("caller_results"),
            d.get("result_words", 0),
            d.get("groups"),
            d.get("return_words", 0),
            d.get("fp_results"),
        )
        return rec

    @staticmethod
    def dump(session, db_kb, go_signatures: GoSignatures):
        data = {
            "go_version": go_signatures.go_version,
            "inferred": go_signatures._inferred,
            "callsites": {str(addr): rec for addr, rec in go_signatures._callsites.items()},
            "closures": {str(addr): type_str for addr, type_str in go_signatures._closures.items()},
            "version": go_signatures.version,
            "versions": go_signatures._versions,
        }
        PluginDataStore.save(session, db_kb, PLUGIN, data)

    @staticmethod
    def load(session, db_kb, kb) -> GoSignatures | None:
        """None when the database holds no Go signature records."""
        data = PluginDataStore.load(session, db_kb, PLUGIN)
        if data is None:
            return None
        from_json = GoSignaturesSerializer._record_from_json
        go_signatures = GoSignatures(kb)
        go_signatures.go_version = data["go_version"]
        go_signatures._inferred = {name: from_json(rec) for name, rec in data["inferred"].items()}
        go_signatures._callsites = {int(addr): from_json(rec) for addr, rec in data["callsites"].items()}
        go_signatures._closures = {int(addr): type_str for addr, type_str in data["closures"].items()}
        # decompilation caches remember the versions they were based on
        go_signatures.version = data["version"]
        go_signatures._versions = data["versions"]
        return go_signatures
