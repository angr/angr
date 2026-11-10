from __future__ import annotations

import json
from typing import Any

from angr.angrdb.models import DbKbPluginData, DbKnowledgeBase


class PluginDataStore:
    """
    Read and write the JSON document of one knowledge base plugin in the ``kb_plugin_data`` table.
    """

    @staticmethod
    def save(session, db_kb: DbKnowledgeBase, plugin: str, data: dict[str, Any] | None) -> None:
        """Replace the stored document of ``plugin``; None removes it."""
        session.query(DbKbPluginData).filter_by(kb=db_kb, plugin=plugin).delete()
        if data is not None:
            session.add(DbKbPluginData(kb=db_kb, plugin=plugin, data=json.dumps(data)))

    @staticmethod
    def load(session, db_kb: DbKnowledgeBase, plugin: str) -> dict[str, Any] | None:
        db_data = session.query(DbKbPluginData).filter_by(kb=db_kb, plugin=plugin).first()
        if db_data is None:
            return None
        return json.loads(db_data.data)

    @staticmethod
    def bytes_map_to_json(d: dict[int, bytes]) -> dict[str, str]:
        return {str(k): v.hex() for k, v in d.items()}

    @staticmethod
    def bytes_map_from_json(d: dict[str, str]) -> dict[int, bytes]:
        return {int(k): bytes.fromhex(v) for k, v in d.items()}
