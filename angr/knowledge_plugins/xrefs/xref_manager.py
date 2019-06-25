
import logging
from collections import defaultdict

from ...serializable import Serializable
from ...protos import xrefs_pb2
from ..plugin import KnowledgeBasePlugin
from .xref import XRef


l = logging.getLogger(name=__name__)


class XRefManager(KnowledgeBasePlugin, Serializable):
    def __init__(self, kb):
        super().__init__()
        self._kb = kb

        self.xrefs_by_ins_addr = defaultdict(set)
        self.xrefs_by_dst = defaultdict(set)

    def add_xref(self, xref):
        self.xrefs_by_ins_addr[xref.ins_addr].add(xref)
        self.xrefs_by_dst[xref.dst].add(xref)

    def add_xrefs(self, xrefs):
        for xref in xrefs:
            self.add_xref(xref)

    def get_xrefs_by_ins_addr(self, ins_addr):
        return self.xrefs_by_ins_addr.get(ins_addr, set())

    def get_xrefs_by_dst(self, dst):
        return self.xrefs_by_dst.get(dst, set())

    def _get_cmsg(cls):
        return xrefs_pb2.XRefs()

    def serialize_to_cmessage(self):
        cmsg = self._get_cmsg()
        # references
        refs = []
        for ref_set in self.xrefs_by_ins_addr.values():
            for ref in ref_set:
                refs.append(ref.serialize_to_cmessage())
        cmsg.refs.extend(refs)
        return cmsg

    @classmethod
    def parse_from_cmessage(cls, cmsg, cfg_model=None, **kwargs):

        model = XRefManager(None)

        # references
        for xref_pb2 in cmsg.refs:
            if xref_pb2.data_ea == -1:
                l.warning("Unknown address of the referenced data item. Ignore the reference at %#x.", xref_pb2.ea)
                continue
            xref = XRef.parse_from_cmessage(xref_pb2)
            if cfg_model is not None:
                xref.memory_data = cfg_model.memory_data[xref_pb2.data_ea]
            model.add_xref(xref)

        return model


KnowledgeBasePlugin.register_default('xrefs', XRefManager)
