from __future__ import annotations

import logging

from sortedcontainers import SortedDict

from angr.knowledge_plugins.plugin import KnowledgeBasePlugin
from angr.protos import xrefs_pb2
from angr.serializable import Serializable

from .spilling_xref import SpillingXrefDict, SpillingXrefDstIndex
from .xref import XRef, XRefType

l = logging.getLogger(name=__name__)


class XrefDict(SortedDict):
    """
    A SortedDict that maps addresses to sets of XRefs.
    It adds defaultdict-like behavior around SortedDict.
    """

    def __missing__(self, key):
        value = set()
        super().__setitem__(key, value)
        return value

    def get_xrefs_in_range(self, start, end):
        """
        Get a set of XRef objects that point to addresses in the given range.
        """
        result = set()
        for k in self.islice(self.bisect_left(start), self.bisect_right(end) + 1):
            result.update(self[k])
        return result


class XRefManager(KnowledgeBasePlugin, Serializable):
    def __init__(self, kb):
        super().__init__(kb=kb)

        rtdb = kb.rtdb if kb is not None else None
        if kb is not None and getattr(kb, "_project", None) is not None:
            self._xrefs_cache_limit = kb._project.get_xrefs_cache_limit()
        else:
            self._xrefs_cache_limit = None

        # xrefs_by_ins_addr is the single owner of all XRef objects; xrefs_by_dst only records the
        # referencing instruction addresses so that evicting an owner entry actually frees its XRefs.
        self.xrefs_by_ins_addr, self.xrefs_by_dst = self._new_indexes(rtdb)

    def _new_indexes(self, rtdb) -> tuple[SpillingXrefDict, SpillingXrefDstIndex]:
        owner = SpillingXrefDict(rtdb, cache_limit=self._xrefs_cache_limit, db_name="xrefs_by_ins")
        dst_index = SpillingXrefDstIndex(rtdb, owner=owner, cache_limit=self._xrefs_cache_limit)
        return owner, dst_index

    def set_kb(self, kb):
        super().set_kb(kb)
        # re-attach the RuntimeDb after unpickling so that xref spilling works again
        rtdb = kb.rtdb
        self.xrefs_by_ins_addr.set_rtdb(rtdb)
        self.xrefs_by_dst.set_rtdb(rtdb)
        self.xrefs_by_dst.set_owner(self.xrefs_by_ins_addr)

    def __setstate__(self, state):
        self.__dict__.update(state)
        # the dst index does not pickle its owner reference; re-attach it
        self.xrefs_by_dst.set_owner(self.xrefs_by_ins_addr)

    def copy(self):
        xm = XRefManager(self._kb)
        xm.xrefs_by_ins_addr = self.xrefs_by_ins_addr.copy()
        xm.xrefs_by_dst = self.xrefs_by_dst.copy()
        xm.xrefs_by_dst.set_owner(xm.xrefs_by_ins_addr)
        return xm

    def clear(self):
        rtdb = self._kb.rtdb if self._kb is not None else None
        self.xrefs_by_ins_addr, self.xrefs_by_dst = self._new_indexes(rtdb)

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
        self.xrefs_by_dst.add_ref(xref.dst, xref.ins_addr)

        for ex in to_remove:
            # the dst-index entry stays: the replacing xref has the same (ins_addr, dst)
            d0.discard(ex)

    def add_xrefs(self, xrefs):
        for xref in xrefs:
            self.add_xref(xref)

    def get_xrefs_by_ins_addr(self, ins_addr):
        return self.xrefs_by_ins_addr.get(ins_addr, set())

    def get_xrefs_by_dst(self, dst):
        return self.xrefs_by_dst.get(dst, set())

    def get_xrefs_by_dst_region(self, start, end):
        """
        Get a set of XRef objects that point to a given address region
        bounded by start and end.
        Will only return absolute xrefs, not relative ones (like SP offsets)
        """
        return self.xrefs_by_dst.get_xrefs_in_range(start, end)

    def get_next_xref_addr_by_dst(self, addr: int) -> int | None:
        """
        Get the next XRef object whose address is greater than or equal to the given address.
        Will only return absolute xrefs, not relative ones (like SP offsets)
        """
        try:
            return next(self.xrefs_by_dst.irange(minimum=addr))
        except StopIteration:
            return None

    def get_xrefs_by_ins_addr_region(self, start, end) -> set[XRef]:
        """
        Get a set of XRef objects that originate at a given address region
        bounded by start and end.  Useful for finding references from a basic block or function.
        """
        return self.xrefs_by_ins_addr.get_xrefs_in_range(start, end)

    # TODO: Maybe add some helpers that accept Function or Block objects for the sake of clean analyses.

    @classmethod
    def _get_cmsg(cls):
        return xrefs_pb2.XRefs()

    def _lookup_cfg_model(self):
        """Find the CFG model whose memory_data map describes the xref targets (for serialization)."""
        if self._kb is not None and "CFGFast" in self._kb.cfgs:
            return self._kb.cfgs["CFGFast"]
        return None

    def serialize_to_cmessage(self):
        # pylint:disable=no-member
        cmsg = self._get_cmsg()
        cfg_model = self._lookup_cfg_model()
        # references
        refs = []
        for ref_set in self.xrefs_by_ins_addr.values():
            for ref in ref_set:
                md = None
                if cfg_model is not None and isinstance(ref.dst, int):
                    md = cfg_model.memory_data.get(ref.dst)
                refs.append(ref.serialize_to_cmessage(memory_data=md))
        cmsg.xrefs.extend(refs)
        return cmsg

    @classmethod
    def parse_from_cmessage(cls, cmsg, cfg_model=None, kb=None, **kwargs):  # pylint:disable=arguments-differ
        model = XRefManager(kb)
        bits = kb._project.arch.bits

        # references
        for xref_pb2 in cmsg.xrefs:
            if xref_pb2.data_ea == -1:
                l.warning("Unknown address of the referenced data item. Ignore the reference at %#x.", xref_pb2.ea)
                continue
            xref = XRef.parse_from_cmessage(xref_pb2, bits=bits)
            model.add_xref(xref)

        return model


KnowledgeBasePlugin.register_default("xrefs", XRefManager)
