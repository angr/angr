#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use,protected-access
"""MemoryData views over the Rust MemoryDataStore and the SortedDict API of CFGModel.memory_data."""

from __future__ import annotations

__package__ = __package__ or "tests.knowledge_plugins.cfg"  # pylint:disable=redefined-builtin

import copy
import pickle
import unittest

from sortedcontainers import SortedDict

from angr.knowledge_plugins.cfg import CFGModel, MemoryData, MemoryDataSort
from angr.knowledge_plugins.cfg.memory_data import MemoryDataDict
from angr.knowledge_plugins.xrefs import XRef, XRefType


def _fields(md: MemoryData) -> tuple:
    return md.addr, md.size, md.reference_size, md.sort, md.max_size, md.pointer_addr, md.content


class TestMemoryDataDict(unittest.TestCase):
    def test_insert_attaches_and_reads_through(self):
        d = MemoryDataDict()
        md = MemoryData(0x1000, 5, MemoryDataSort.String, max_size=16)
        md.content = b"hello"
        d[0x1000] = md
        assert md._store is d.store
        assert d[0x1000] is md
        assert _fields(md) == (0x1000, 5, None, "string", 16, None, b"hello")
        # writes through the view land in the store
        md.size = 6
        md.sort = "a sort nobody declared"
        md.reference_size = 9
        assert d.store.fields(0x1000) == (6, 9, "a sort nobody declared", 16, None, b"hello")

    def test_overwrite_and_delete_detach_old_objects(self):
        d = MemoryDataDict()
        old = MemoryData(0x10, 4, MemoryDataSort.Integer)
        d[0x10] = old
        new = MemoryData(0x10, 8, MemoryDataSort.PointerArray)
        d[0x10] = new
        # the replaced object keeps its own fields, like an object dropped from a dict
        assert old._store is None
        assert _fields(old) == (0x10, 4, None, "integer", None, None, None)
        assert d[0x10] is new and new.size == 8
        del d[0x10]
        assert new._store is None and new.size == 8
        assert 0x10 not in d and len(d) == 0
        with self.assertRaises(KeyError):
            _ = d[0x10]

    def test_sorted_dict_api(self):
        d = MemoryDataDict()
        for a in (0x30, 0x10, 0x20, 0x40):
            d[a] = MemoryData(a, 1, MemoryDataSort.Unknown)
        assert list(d) == d.keys() == [0x10, 0x20, 0x30, 0x40]
        assert [md.addr for md in d.values()] == [0x10, 0x20, 0x30, 0x40]
        assert list(d.irange(0x11)) == [0x20, 0x30, 0x40]
        assert list(d.irange(minimum=0x20, maximum=0x30)) == [0x20, 0x30]
        assert list(d.irange(0x20, 0x30, inclusive=(False, False))) == []
        assert list(d.irange(0x10, 0x30, reverse=True)) == [0x30, 0x20, 0x10]
        assert d.bisect_left(0x20) == 1 and d.bisect_right(0x20) == 2
        assert d.peekitem(-1)[0] == 0x40
        assert d.get(0x99) is None and d.get("x") is None and "x" not in d
        assert d.pop(0x40).addr == 0x40 and d.pop(0x40, None) is None
        assert d.setdefault(0x50, MemoryData(0x50, 2, None)).size == 2

    def test_any_int_key_and_size(self):
        d = MemoryDataDict()
        d[0x10] = MemoryData(0x10, 1 << 70, MemoryDataSort.Unknown, max_size=-(1 << 70))
        assert d[0x10].size == 1 << 70 and d[0x10].max_size == -(1 << 70)
        for key in (-1, 1 << 64, "x"):
            assert key not in d and d.get(key) is None
        assert list(d.irange(-5, 1 << 65)) == [0x10]
        assert list(d.irange(1 << 64)) == [] and list(d.irange(maximum=-1)) == []

    def test_copy_has_its_own_records(self):
        model = CFGModel("CFGFast")
        md = MemoryData(0x10, 4, MemoryDataSort.String)
        model.memory_data[0x10] = md
        model.insn_addr_to_memory_data[0x400000] = md
        clone = model.copy()
        assert clone.memory_data[0x10] is not md
        assert clone.insn_addr_to_memory_data[0x400000] is clone.memory_data[0x10]
        clone.memory_data[0x10].size = 99
        assert md.size == 4

    def test_model_accepts_a_sorted_dict(self):
        model = CFGModel("CFGFast")
        md = MemoryData(0x20, 3, MemoryDataSort.String)
        model.memory_data = SortedDict({0x20: md})
        assert isinstance(model.memory_data, MemoryDataDict)
        assert model.memory_data[0x20] is md

    def test_add_memory_data(self):
        model = CFGModel("CFGFast")
        assert model.add_memory_data(0x10, MemoryDataSort.Integer, 4)
        assert not model.add_memory_data(0x10, MemoryDataSort.String, 8)
        assert model.add_memory_data(0x20, None)
        assert _fields(model.memory_data[0x10]) == (0x10, 4, None, "integer", 4, None, None)
        assert _fields(model.memory_data[0x20]) == (0x20, 0, None, "unknown", None, None, None)


class TestMemoryDataSerialization(unittest.TestCase):
    def _model(self) -> CFGModel:
        model = CFGModel("CFGFast")
        md = MemoryData(0x1000, 6, MemoryDataSort.String, max_size=32, reference_size=12)
        md.content = b"string"
        model.memory_data[0x1000] = md
        model.memory_data[0x2000] = MemoryData(0x2000, None, None, pointer_addr=0x1000)
        model.insn_addr_to_memory_data[0x400010] = md
        return model

    def test_pickle_keeps_view_identity(self):
        model = self._model()
        xref = XRef(
            ins_addr=0x400010,
            block_addr=0x400000,
            stmt_idx=1,
            memory_data=model.memory_data[0x1000],
            xref_type=XRefType.Offset,
        )
        model2, xref2 = pickle.loads(pickle.dumps((model, xref)))
        md2 = model2.memory_data[0x1000]
        assert xref2.memory_data is md2 and model2.insn_addr_to_memory_data[0x400010] is md2
        assert _fields(md2) == (0x1000, 6, 12, "string", 32, None, b"string")
        assert _fields(model2.memory_data[0x2000]) == (0x2000, None, None, None, None, 0x1000, None)

    def test_copies(self):
        model = self._model()
        md = model.memory_data[0x1000]
        shallow = copy.copy(md)
        assert shallow._store is None and _fields(shallow) == _fields(md)
        shallow.size = 1
        assert md.size == 6
        xref = XRef(ins_addr=0x400010, memory_data=md, xref_type=XRefType.Offset)
        memory_data2, xref2 = copy.deepcopy((model.memory_data, xref))
        assert memory_data2.store is not model.memory_data.store
        assert xref2.memory_data is memory_data2[0x1000] and _fields(xref2.memory_data) == _fields(md)

    def test_legacy_pickle_state(self):
        # MemoryData pickled by an older angr: (None, slots) state with the public field names
        md = MemoryData.__new__(MemoryData)
        md.__setstate__(
            (
                None,
                {
                    "addr": 0x30,
                    "size": 4,
                    "reference_size": None,
                    "sort": "integer",
                    "max_size": 8,
                    "pointer_addr": None,
                    "content": None,
                },
            )
        )
        assert _fields(md) == (0x30, 4, None, "integer", 8, None, None)
        model = CFGModel("CFGFast")
        # older models pickled memory_data as a SortedDict of detached objects
        model.__setstate__({"memory_data": SortedDict({0x30: md})})
        assert model.memory_data[0x30] is md and md._store is model.memory_data.store

    def test_protobuf_round_trip(self):
        model = self._model()
        cmsg = model.serialize_to_cmessage()
        assert [m.ea for m in cmsg.memory_data] == [0x1000, 0x2000]
        model2 = CFGModel.parse_from_cmessage(cmsg)
        md = model2.memory_data[0x1000]
        # protobuf carries addr, size, reference_size and sort
        assert _fields(md) == (0x1000, 6, 12, "string", None, None, None)
        assert _fields(model2.memory_data[0x2000]) == (0x2000, None, None, None, None, None, None)


if __name__ == "__main__":
    unittest.main()
