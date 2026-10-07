from __future__ import annotations

import json
import logging

from angr.angrdb.models import DbCallsitePrototype
from angr.knowledge_plugins.callsite_prototypes import CallsitePrototypeKind, CallsitePrototypes
from angr.knowledge_plugins.functions.function_parser import CallingConventionSerializer
from angr.sim_type import SimType, SimTypeFunction
from angr.utils.types import dereference_simtype, find_type_refs, make_type_reference, type_collections_for_lib

l = logging.getLogger(__name__)


class CallsitePrototypesSerializer:
    """
    Serialize/unserialize call-site prototypes of every flavor to/from a database session.
    """

    @staticmethod
    def dump(session, db_kb, callsite_prototypes: CallsitePrototypes):
        # rewritten wholesale, like patterns, so removals persist
        session.query(DbCallsitePrototype).filter_by(kb=db_kb).delete()
        type_collections = type_collections_for_lib(None)
        for flavor in callsite_prototypes.flavors:
            for addr, kind, cc, prototype in callsite_prototypes.items(flavor):
                proto_ref = make_type_reference(prototype, type_collections=type_collections)
                session.add(
                    DbCallsitePrototype(
                        kb=db_kb,
                        flavor=flavor,
                        addr=addr,
                        kind=kind.value,
                        cc=json.dumps(CallingConventionSerializer.to_json(cc)),
                        prototype=json.dumps(proto_ref.to_json()),
                    )
                )

    @staticmethod
    def load(session, db_kb, kb) -> CallsitePrototypes:  # pylint:disable=unused-argument
        callsite_prototypes = CallsitePrototypes(kb)
        project = kb._project
        if project is None:
            return callsite_prototypes
        type_collections = type_collections_for_lib(None)
        for db_entry in db_kb.callsite_prototypes:
            cc = CallingConventionSerializer.from_json(json.loads(db_entry.cc), project.arch)
            if cc is None:
                continue
            proto = SimType.from_json(json.loads(db_entry.prototype))
            if not isinstance(proto, SimTypeFunction):
                l.warning("Unexpected type of call-site prototype deserialized: %s", type(proto))
                continue
            if find_type_refs(proto):
                proto = dereference_simtype(proto, type_collections, keep_missing=True)
            proto = proto.with_arch(project.arch)
            assert isinstance(proto, SimTypeFunction)
            callsite_prototypes.set_prototype(
                db_entry.addr, cc, proto, kind=CallsitePrototypeKind(db_entry.kind), flavor=db_entry.flavor
            )
        return callsite_prototypes
