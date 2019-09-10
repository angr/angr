
import logging
from collections import defaultdict

from ...serializable import Serializable
from ...protos import xrefs_pb2
from ..plugin import KnowledgeBasePlugin
from .xref import XRef, XRefType


l = logging.getLogger(name=__name__)


class XRefManager(KnowledgeBasePlugin, Serializable):
    def __init__(self, kb):
        super().__init__()
        self._kb = kb

        self.xrefs_by_ins_addr = defaultdict(set)
        self.xrefs_by_dst = defaultdict(set)

    def copy(self):
        xm = XRefManager(self._kb)
        xm.xrefs_by_ins_addr = self.xrefs_by_ins_addr.copy()
        xm.xrefs_by_dst = self.xrefs_by_dst.copy()
        return xm

    def add_xref(self, xref):
        to_remove = set()
        # Overwrite existing "offset" refs
        if xref.type != XRefType.Offset:
            existing = self.get_xrefs_by_ins_addr(xref.ins_addr)
            if existing:
                for ex in existing:
                    if ex.dst == xref.dst and ex.type == XRefType.Offset:
                        # We want to remove this one and replace it with the new one
                        to_remove.add(ex)

        d0 = self.xrefs_by_ins_addr[xref.ins_addr]
        d0.add(xref)
        d1 = self.xrefs_by_dst[xref.dst]
        d1.add(xref)

        for ex in to_remove:
            d0.discard(ex)
            d1.discard(ex)

    def add_xrefs(self, xrefs):
        for xref in xrefs:
            self.add_xref(xref)

    def get_xrefs_by_ins_addr(self, ins_addr):
        return self.xrefs_by_ins_addr.get(ins_addr, set())

    def get_xrefs_by_dst(self, dst):
        return self.xrefs_by_dst.get(dst, set())

    @classmethod
    def _get_cmsg(cls):
        return xrefs_pb2.XRefs()

    def serialize_to_cmessage(self):
        # pylint:disable=no-member
        cmsg = self._get_cmsg()
        # references
        refs = []
        for ref_set in self.xrefs_by_ins_addr.values():
            for ref in ref_set:
                refs.append(ref.serialize_to_cmessage())
        cmsg.xrefs.extend(refs)
        return cmsg

    @classmethod
    def parse_from_cmessage(cls, cmsg, cfg_model=None, **kwargs):  # pylint:disable=arguments-differ

        model = XRefManager(None)

        # references
        for xref_pb2 in cmsg.xrefs:
            if xref_pb2.data_ea == -1:
                l.warning("Unknown address of the referenced data item. Ignore the reference at %#x.", xref_pb2.ea)
                continue
            xref = XRef.parse_from_cmessage(xref_pb2)
            if cfg_model is not None:
                xref.memory_data = cfg_model.memory_data[xref_pb2.data_ea]
            model.add_xref(xref)

        return model


KnowledgeBasePlugin.register_default('xrefs', XRefManager)
