#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use,protected-access
"""The CFBlanket(kb=...) build reads the local blocks of spilled functions without loading them."""

from __future__ import annotations

__package__ = __package__ or "tests.analyses.cfg"  # pylint:disable=redefined-builtin

import os
import unittest

import angr
from angr.analyses.cfg.cfb import CFBlanket
from angr.angrdb.v1 import AngrDbV1
from angr.codenode import BlockNode
from angr.knowledge_plugins.functions.function_manager import SpillingFunctionDict
from angr.rustylib.cfb import KIND_BLOCK, KIND_BLOCK_BYTES, KIND_PYOBJ
from tests.analyses.cfg.cfb_reference import ReferenceCFBlanket
from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")


class _ReferenceCFBlanket(CFBlanket):
    def _add_function_blocks(self) -> None:
        for func in self.kb.functions.values():
            self.add_function(func)


def _block_desc(block) -> tuple:
    return block.addr, block.size, block.thumb, block._bytes


def _deep(cfb) -> list:
    rows = []
    for a, o in cfb._blanket.items():
        if isinstance(o, angr.Block):
            prof = (o._opt_level, o._collect_data_refs, o._cross_insn_opt, o._extra_stop_points, o._backup_state)
            try:
                data = o.bytes
            except KeyError:
                # unmapped: only user-supplied bytes exist
                data = None
            rows.append((a, "Block", o.addr, o.size, o.thumb, prof, data))
        else:
            rows.append((a, type(o).__name__, o.size))
    return rows


def _kinds(cfb) -> set[int]:
    return {kind for _, kind, *_ in cfb._store.state()[0]}


def _items(cfb) -> list:
    return [(a, type(o).__name__, o.size, getattr(o, "thumb", None)) for a, o in cfb._blanket.items()]


class TestCFBFinalBuild(unittest.TestCase):
    def _project(self, binary: str, cache_limit: int | None):
        cache_limits = {"functions": cache_limit} if cache_limit is not None else {}
        proj = angr.Project(os.path.join(test_location, binary), auto_load_libs=False, cache_limits=cache_limits)
        proj.analyses.CFGFast(normalize=True)
        return proj

    def _specs_as_blocks(self, proj) -> list:
        return [
            (addr, [_block_desc(proj.factory.block(a, size=s, byte_string=b)) for a, s, b in specs])
            for addr, specs in proj.kb.functions.iter_local_block_specs()
        ]

    def _reference(self, proj) -> list:
        # loads every spilled function
        return [(f.addr, [_block_desc(b) for b in f.blocks]) for f in proj.kb.functions.values()]

    def test_specs_match_function_blocks(self):
        for binary in ("x86_64/fauxware", "armel/fauxware"):
            for cache_limit in (None, 3):
                proj = self._project(binary, cache_limit)
                fmap = proj.kb.functions._function_map
                spilled = set(proj.kb.functions._spilled_addrs)
                lru = list(fmap._lru_order) if isinstance(fmap, SpillingFunctionDict) else []
                got = self._specs_as_blocks(proj)
                if cache_limit is not None:
                    assert isinstance(fmap, SpillingFunctionDict) and spilled
                    # nothing was loaded, and the LRU order is untouched
                    assert set(proj.kb.functions._spilled_addrs) == spilled
                    assert list(fmap._lru_order) == lru
                assert got == self._reference(proj), (binary, cache_limit)

    def test_legacy_records(self):
        proj = self._project("x86_64/fauxware", 3)
        fm = proj.kb.functions
        items = [(f.addr, AngrDbV1.serialize_function(f).SerializeToString()) for f in fm.values()]
        fm._function_map.bulk_import_serialized(items)
        assert len(fm._spilled_addrs) == len(items)
        got = self._specs_as_blocks(proj)
        assert got == self._reference(proj)

    def test_user_supplied_bytes(self):
        proj = self._project("x86_64/fauxware", 2)
        fm = proj.kb.functions
        func = fm.function(addr=0x500000, create=True)
        assert func is not None
        fm._add_node(0x500000, BlockNode(0x500000, 4, bytestr=b"\x90" * 4))
        # cached, with its CodeNode materialized: Function.blocks passes the user-supplied bytes on
        specs = dict(fm.iter_local_block_specs())
        assert specs[0x500000] == [(0x500000, 4, b"\x90" * 4)]
        assert [_block_desc(b) for b in func.blocks] == [(0x500000, 4, False, b"\x90" * 4)]
        # spilled: a freshly loaded Function has no CodeNode objects, so Function.blocks reads the loader
        fm.cache_limit = 1
        _ = fm[next(a for a in fm if a != 0x500000)]
        assert 0x500000 in fm._spilled_addrs
        specs = dict(fm.iter_local_block_specs())
        assert specs[0x500000] == [(0x500000, 4, None)]
        assert 0x500000 in fm._spilled_addrs
        assert [(b.addr, b.size) for b in fm[0x500000].blocks] == [(0x500000, 4)]

    def test_cfb_items_match(self):
        for binary in ("x86_64/fauxware", "armel/fauxware"):
            proj = self._project(binary, 3)
            new = _items(proj.analyses[CFBlanket].prep(kb=proj.kb)(exclude_region_types={"kernel", "tls"}))
            ref = _items(proj.analyses[_ReferenceCFBlanket].prep(kb=proj.kb)(exclude_region_types={"kernel", "tls"}))
            assert new == ref, binary

    def _both(self, proj) -> tuple:
        ex = {"kernel", "tls"}
        new = proj.analyses[CFBlanket].prep(kb=proj.kb)(exclude_region_types=ex)
        ref = proj.analyses[ReferenceCFBlanket].prep(kb=proj.kb)(exclude_region_types=ex)
        return new, ref

    def test_native_blocks_match_eager(self):
        # no Blocks are created at build time, and the materialized ones equal the eager build's
        for binary in ("x86_64/fauxware", "armel/fauxware"):
            for cache_limit in (None, 3):
                proj = self._project(binary, cache_limit)
                spilled = set(proj.kb.functions._spilled_addrs)
                new, ref = self._both(proj)
                assert KIND_BLOCK in _kinds(new) and KIND_PYOBJ not in _kinds(new)
                assert set(proj.kb.functions._spilled_addrs) == spilled
                assert _deep(new) == _deep(ref), (binary, cache_limit)

    def test_native_blocks_legacy_and_user_bytes(self):
        proj = self._project("x86_64/fauxware", 3)
        fm = proj.kb.functions
        func = fm.function(addr=0x500000, create=True)
        assert func is not None
        fm._add_node(0x500000, BlockNode(0x500000, 4, bytestr=b"\x90" * 4))
        new, ref = self._both(proj)
        assert KIND_BLOCK_BYTES in _kinds(new)
        assert new[0x500000].bytes == b"\x90" * 4
        assert _deep(new) == _deep(ref)
        # angrDb v1 records carry no graph blob
        items = [(f.addr, AngrDbV1.serialize_function(f).SerializeToString()) for f in fm.values()]
        fm._function_map.bulk_import_serialized(items)
        new, ref = self._both(proj)
        assert _deep(new) == _deep(ref)

    def test_patches_keep_eager_blocks(self):
        proj = self._project("x86_64/fauxware", None)
        main = proj.kb.functions["main"]
        proj.kb.patches.add_patch(main.addr, b"\xcc")
        new, ref = self._both(proj)
        # Blocks load their bytes when created with patches present, so they are created at build time
        assert KIND_BLOCK not in _kinds(new) and KIND_PYOBJ in _kinds(new)
        assert new[main.addr].bytes[:1] == b"\xcc"
        assert _deep(new) == _deep(ref)


if __name__ == "__main__":
    unittest.main()
