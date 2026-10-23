#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use,protected-access
from __future__ import annotations

__package__ = __package__ or "tests.analyses.cfg"  # pylint:disable=redefined-builtin

import io
import os
import random
import unittest

import angr
from angr.analyses.cfg.loader_snapshot import build_loader_snapshot
from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")

BLOB_BASE = 0x400000


def _blob_project(data: bytes, arch: str) -> angr.Project:
    return angr.Project(
        io.BytesIO(data),
        main_opts={"backend": "blob", "arch": arch, "base_addr": BLOB_BASE, "entry_point": BLOB_BASE},
        auto_load_libs=False,
    )


def _reset_caches(loader) -> None:
    # cle caches the last object/section/segment hit; with overlapping regions its answers then depend on query
    # history, which the stateless snapshot does not model
    loader._last_object = None
    for obj in loader.all_objects:
        obj._last_section = None
        obj._last_segment = None


def _sym(sym) -> tuple[int, int, bool, str] | None:
    return None if sym is None else (sym.rebased_addr, sym.size, sym.is_function, sym.name)


class TestLoaderSnapshot(unittest.TestCase):
    """The snapshot must answer every query exactly as cle (and CFGBase) do."""

    def _check(self, proj: angr.Project, samples: int = 1500):
        loader = proj.loader
        snap = build_loader_snapshot(loader, proj.arch)
        objs = loader.all_objects
        rnd = random.Random(0x5EED)

        addrs = set()
        for obj in objs:
            for region in list(obj.sections) + list(obj.segments):
                for a in (region.vaddr, region.vaddr + region.memsize - 1, region.vaddr + region.memsize):
                    addrs.update((a - 1, a, a + 1))
            addrs.update((obj.min_addr - 1, obj.min_addr, obj.max_addr, obj.max_addr + 1))
        for start, backer in loader.memory.backers():
            addrs.update((start - 1, start, start + len(backer) - 1, start + len(backer)))
        lo, hi = loader.min_addr, loader.max_addr
        addrs.update(rnd.randrange(max(lo - 0x1000, 0), hi + 0x1000) for _ in range(samples))
        addrs = sorted(a for a in addrs if a >= 0)

        for addr in addrs:
            try:
                expected_byte = loader.memory[addr]
            except KeyError:
                expected_byte = None
            assert snap.load_byte(addr) == expected_byte, hex(addr)

            for size in (1, 2, 4, 8):
                try:
                    expected_word = loader.memory.unpack_word(addr, size=size)
                except KeyError:
                    expected_word = None
                assert snap.load_word(addr, size) == expected_word, (hex(addr), size)

            try:
                expected_bytes = loader.memory.load(addr, 37)
            except KeyError:
                expected_bytes = None
            assert snap.load_bytes(addr, 37) == expected_bytes, hex(addr)

            for membership_check in (True, False):
                _reset_caches(loader)
                obj = loader.find_object_containing(addr, membership_check=membership_check)
                idx = snap.find_object_containing(addr, membership_check)
                assert (objs[idx] if idx is not None else None) is obj, (hex(addr), membership_check)

            _reset_caches(loader)
            sec = snap.find_section_containing(addr)
            assert (objs[sec[0]].sections[sec[1]] if sec is not None else None) is loader.find_section_containing(
                addr
            ), hex(addr)
            _reset_caches(loader)
            seg = snap.find_segment_containing(addr)
            assert (objs[seg[0]].segments[seg[1]] if seg is not None else None) is loader.find_segment_containing(
                addr
            ), hex(addr)

            _reset_caches(loader)
            assert snap.floor_symbol(addr) == _sym(loader.find_symbol(addr, fuzzy=True)), hex(addr)

        for obj in objs:
            for sym in obj.symbols:
                assert snap.symbol_at(sym.rebased_addr) == _sym(loader.find_symbol(sym.rebased_addr))

        cfg = proj.analyses.CFGFast(
            regions=[(proj.entry, proj.entry + 1)],
            start_at_entry=False,
            symbols=False,
            function_prologues=False,
            eh_frame=False,
            data_references=False,
            force_smart_scan=False,
        )
        for force_segment in (False, True):
            assert snap.executable_memory_regions(None, force_segment) == cfg._executable_memory_regions(
                force_segment=force_segment
            )
        for addr in addrs[:: max(1, len(addrs) // 300)]:
            for delta in (1, 0x40, 0x1000, -0x10):
                b = addr + delta
                if b < 0:
                    continue
                _reset_caches(loader)
                assert snap.addrs_belong_to_same_section(addr, b) == cfg._addrs_belong_to_same_section(addr, b)
                _reset_caches(loader)
                assert snap.addrs_belong_to_same_segment(addr, b) == cfg._addrs_belong_to_same_segment(addr, b)

    def test_elf_amd64(self):
        self._check(angr.Project(os.path.join(test_location, "x86_64", "fauxware"), auto_load_libs=False))

    def test_elf_armel(self):
        self._check(angr.Project(os.path.join(test_location, "armel", "fauxware"), auto_load_libs=False))

    def test_elf_ppc64_big_endian(self):
        self._check(angr.Project(os.path.join(test_location, "ppc64", "fauxware"), auto_load_libs=False))

    def test_elf_mips_with_libs(self):
        proj = angr.Project(
            os.path.join(test_location, "mips", "fauxware"),
            auto_load_libs=True,
            ld_path=[os.path.join(test_location, "mips")],
        )
        self._check(proj)

    def test_pe(self):
        proj = angr.Project(
            os.path.join(
                test_location, "i386", "windows", "0245fc3455f66354cef5b73de12318f881e89a7f2af19b5592349ce1d7de2017"
            ),
            auto_load_libs=False,
        )
        self._check(proj)

    def test_macho(self):
        self._check(angr.Project(os.path.join(test_location, "x86_64", "fauxware.macho"), auto_load_libs=False))

    def test_blob(self):
        with open(os.path.join(test_location, "armel", "fauxware"), "rb") as f:
            data = f.read()
        self._check(_blob_project(data, "ARMEL"))


if __name__ == "__main__":
    unittest.main()
