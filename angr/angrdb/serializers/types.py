from __future__ import annotations

import logging

from angr.knowledge_plugins.types import TypesStore
from angr.sim_type import SimType, TypeRef
from angr.utils.types import relink_typerefs

from .plugin_data import PluginDataStore

l = logging.getLogger(__name__)

PLUGIN = "types"


class TypesStoreSerializer:
    """
    Serialize/unserialize the types that a TypesStore owns (not the ones in ALL_TYPES) to/from a database session.
    """

    @staticmethod
    def dump(session, db_kb, types: TypesStore):
        data = {"types": [types.get_own(name).to_json() for name in types.iter_own_keys()]}
        PluginDataStore.save(session, db_kb, PLUGIN, data)

    @staticmethod
    def load(session, db_kb, kb) -> TypesStore:
        types = TypesStore(kb)
        data = PluginDataStore.load(session, db_kb, PLUGIN)
        if data is None:
            return types
        typerefs: dict[str, TypeRef] = {}
        for d in data["types"]:
            ref = SimType.from_json(d)
            if not isinstance(ref, TypeRef):
                l.warning("Unexpected type of TypesStore entry deserialized: %s", type(ref))
                continue
            typerefs[ref.name] = ref
        # nested references to other entries were written out as copies; make them share the entries again
        for ref in typerefs.values():
            ref.type = relink_typerefs(ref.type, typerefs)
        for name, ref in typerefs.items():
            types[name] = ref
        return types
