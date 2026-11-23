#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use,protected-access
from __future__ import annotations

__package__ = __package__ or "tests.analyses.cfg"  # pylint:disable=redefined-builtin

import io
import os
import random
import re
import struct
import unittest

import archinfo

import angr
from angr.analyses.cfg.loader_snapshot import build_loader_snapshot
from angr.rustylib import SegmentList
from angr.rustylib.cfg_scan import LinearSweep, regex_find_all
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


class TestPrologueRegexTranslation(unittest.TestCase):
    def test_archinfo_prologs_match_python_re(self):
        rnd = random.Random(1)
        blobs = [rnd.randbytes(0x10000)]
        for path in (("x86_64", "fauxware"), ("armel", "fauxware"), ("mips", "fauxware"), ("ppc64", "fauxware")):
            with open(os.path.join(test_location, *path), "rb") as f:
                blobs.append(f.read())

        patterns = set()
        for arch in archinfo.all_arches:
            patterns.update(arch.function_prologs)
            if isinstance(arch, archinfo.ArchARM):
                patterns.update(arch.thumb_prologs)

        untranslated = set()
        for pattern in patterns:
            for blob in blobs:
                starts = regex_find_all(pattern, blob)
                if starts is None:
                    untranslated.add(pattern)
                    break
                assert starts == [mo.start() for mo in re.finditer(pattern, blob)], pattern
        # look-around stays with Python's re (through the fallback callback)
        assert all(b"(?!" in p or b"(?=" in p or b"(?<" in p for p in untranslated), untranslated


class TestLinearSweep(unittest.TestCase):
    def _sweep(self, data: bytes, arch: str, check_xfg: bool = False) -> LinearSweep:
        proj = _blob_project(data, arch)
        snap = build_loader_snapshot(proj.loader, proj.arch)
        return LinearSweep(snap, [(BLOB_BASE, BLOB_BASE + len(data))], [], 2048, 0.6, 16483, check_xfg)

    def test_byte_classifiers(self):
        data = b"\x90" * 4 + b"\x00" * 5 + b"\xab" * 20 + bytes(range(0xF0, 0x100)) + bytes(range(0x10)) + b"\x41"
        sweep = self._sweep(data, "AMD64")
        assert sweep.scan_for_repeating_bytes(BLOB_BASE + 4, 0x00) == 5
        # with no byte given, the first byte only seeds the run and is not counted
        assert sweep.scan_for_repeating_bytes(BLOB_BASE + 9, None, 16) == 19
        assert sweep.scan_for_repeating_bytes(BLOB_BASE + 9, None, 20) == 0
        assert sweep.scan_for_monotonic_byte_ramp(BLOB_BASE + 29) == 32
        assert sweep.repeating_byte_run_length(BLOB_BASE + 9, 16) == 20
        assert sweep.repeating_byte_run_length(BLOB_BASE + 9, 16, ignore=0xAB) == 0
        # a callback overrides snapshot reads (CFGFast with a base state)
        assert sweep.scan_for_repeating_bytes(BLOB_BASE, 0x90, 2, byte_loader=lambda _addr: 0x90) == len(data)

    def test_strings(self):
        data = b"\x01" + b"Hello, world!\x00" + "Wide one".encode("utf-16-le") + b"\x00\x00" + b"ABCDEpG12345\x00"
        sweep = self._sweep(data, "AMD64")
        assert sweep.scan_for_printable_strings(BLOB_BASE + 1) == 14
        assert sweep.scan_for_printable_strings(BLOB_BASE) == 0
        assert sweep.scan_for_printable_widestrings(BLOB_BASE + 15) == 18
        # on ARM, a string is cut at an embedded "bx lr"
        arm = self._sweep(data, "ARMEL")
        assert arm.scan_for_printable_strings(BLOB_BASE + 33) == 5

    def test_fp_pointers_xfg(self):
        doubles = b"".join(struct.pack("<d", v) for v in (1.5, 2.25, 3.125, -4.0))
        pointers = b"".join(struct.pack("<Q", BLOB_BASE + o) for o in (0, 8, 16))
        xfg = struct.pack("<Q", 0x8000_0600_1050_0070)
        data = doubles + struct.pack("<d", 1.5) * 4 + pointers + xfg + b"\x00" * 8
        sweep = self._sweep(data, "AMD64", check_xfg=True)
        assert sweep.scan_for_fp_constants(BLOB_BASE) == 64
        # a run of one repeated value is not a table
        assert sweep.scan_for_fp_constants(BLOB_BASE + 32) == 0
        assert sweep.scan_for_consecutive_pointers(BLOB_BASE + 64, 1) == 3
        assert sweep.scan_for_mixed_pointers(BLOB_BASE + 64, 3, 6) == 5
        assert sweep.scan_for_win_xfg_hash(BLOB_BASE + 88)
        assert not sweep.scan_for_win_xfg_hash(BLOB_BASE)

    def test_next_code_addr(self):
        code = bytes.fromhex("554889e531c05dc3")
        data = code + b"Hello, world!\x00" + b"\xcc" * 7 + b"\x00" * 9 + b"\x90" * 20 + code
        sweep = self._sweep(data, "AMD64")
        seg_list = SegmentList()
        seg_list.occupy(BLOB_BASE, 8, "code")
        addr, requests = sweep.next_code_addr(seg_list)
        # recorded on master's CFGFast._next_code_addr
        assert addr == BLOB_BASE + 57
        assert requests == [
            (BLOB_BASE + 8, 14, "string"),
            (BLOB_BASE + 22, 7, "alignment"),
            (BLOB_BASE + 29, 9, "alignment"),
            (BLOB_BASE + 38, 19, "unknown"),
        ]
        assert seg_list.occupied_by_sort(BLOB_BASE + 56) == "nodecode"
        assert seg_list.occupied_by_sort(BLOB_BASE + 57) is None
        assert sweep.next_addr == BLOB_BASE + 8


# MemoryData of a complete linear sweep over crafted blobs, as recorded on master
BLOB_SWEEP_EXPECTED = {
    "AMD64": [
        (8, 14, "string"),
        (22, 34, "unicode"),
        (32, 24, "unicode"),
        (56, 7, "alignment"),
        (63, 9, "alignment"),
        (64, 0, "unknown"),
        (72, 19, "unknown"),
        (136, 64, "pointer-array"),
    ],
    "ARMEL": [
        (8, 8, "string"),
        (18, 14, "string"),
        (32, 2, "alignment"),
        (34, 2, "alignment"),
        (36, 32, "fp"),
        (68, 2, "alignment"),
    ],
    "PPC32": [
        (8, 40, "fp"),
        (12, 0, "unknown"),
        (16, 0, "unknown"),
        (20, 0, "unknown"),
        (48, 24, "pointer-array"),
        (72, 16, "string"),
        (88, 3, "alignment"),
        (91, 3, "string"),
        (97, 3, "unknown"),
    ],
}


def _blob_amd64() -> bytes:
    code = bytes.fromhex("554889e531c05dc3")
    b = bytearray(code)
    b += b"Hello, world!\x00"
    b += "Wide string here".encode("utf-16-le") + b"\x00\x00"
    b += b"\xcc" * 7 + b"\x00" * 9 + b"\x90" * 20 + bytes(range(0x80, 0xA0))
    b += b"\x00" * (-len(b) % 8)
    b += b"".join(struct.pack("<d", v) for v in (1.5, 2.25, 3.125, -4.0, 0.5))
    b += b"".join(struct.pack("<Q", BLOB_BASE + o) for o in (0, 8, 0x20, 0x40))
    b += b"\x11\x22\x33\x44\x55\x66\x77" + code
    return bytes(b)


def _blob_armel() -> bytes:
    b = bytearray(b"\x00\x00\xa0\xe3\x1e\xff\x2f\xe1")  # mov r0, #0; bx lr
    b += b"ABCDEFGHpGJKLMNOPQRSTUV\x00"
    b += b"\x00" * (-len(b) % 4)
    b += b"".join(struct.pack("<f", v) for v in (1.5, 2.25, 3.125, -4.0, 0.5, 6.0, 7.5, 8.25, 9.0))
    b += b"\x00" * (-len(b) % 4) + b"\x00\x00\xa0\xe3\x1e\xff\x2f\xe1"
    return bytes(b)


def _blob_ppc32() -> bytes:
    b = bytearray(b"\x38\x60\x00\x00\x4e\x80\x00\x20")  # li r3, 0; blr
    b += b"\x00" * (-len(b) % 8)
    b += b"".join(struct.pack(">d", v) for v in (1.5, 2.25, 3.125, -4.0, 0.5))
    b += b"".join(struct.pack(">I", BLOB_BASE + o) for o in (0, 4, 8, 0xC, 0x10, 0x14))
    b += b"Big endian text\x00" + b"\x00" * 3 + b"\x38\x60\x00\x00\x4e\x80\x00\x20"
    return bytes(b)


class TestCompleteScanOnBlobs(unittest.TestCase):
    def _check(self, data: bytes, arch: str):
        for with_base_state in (False, True):
            proj = _blob_project(data, arch)
            kw = {"base_state": proj.factory.blank_state()} if with_base_state else {}
            cfg = proj.analyses.CFGFast(force_complete_scan=True, force_smart_scan=False, **kw)
            mds = sorted((md.addr - BLOB_BASE, md.size, md.sort) for md in cfg.memory_data.values())
            assert mds == BLOB_SWEEP_EXPECTED[arch], (arch, with_base_state)

    def test_amd64(self):
        self._check(_blob_amd64(), "AMD64")

    def test_armel(self):
        self._check(_blob_armel(), "ARMEL")

    def test_ppc32(self):
        self._check(_blob_ppc32(), "PPC32")


if __name__ == "__main__":
    unittest.main()
