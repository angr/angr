#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,disable=no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses"  # pylint:disable=redefined-builtin

import os.path
import unittest

import angr
import angr.flirt
from angr.analyses.cfg.cfg_fast import CFGFast
from tests.common import bin_location

# A FLIRT module is anchored at the first function of the object file it was built from, and it names all of its
# public functions at their offsets from that anchor. Scoping the CFG to a few regions keeps these tests off a
# whole-binary CFG recovery (~28s locally); each region has to cover either a function whose name is asserted or
# the anchor whose module supplies that name.
STATIC_LIBC_BINARY = os.path.join(bin_location, "tests", "x86_64", "elf_with_static_libc_ubuntu_2004_stripped")
STATIC_LIBC_SIG = os.path.join(bin_location, "tests", "x86_64", "libc_ubuntu_2004.sig")


def load_static_libc(regions: list[tuple[int, int]]) -> tuple[angr.Project, CFGFast]:
    proj = angr.Project(STATIC_LIBC_BINARY, auto_load_libs=False, load_debug_info=False)
    cfg = proj.analyses.CFGFast(show_progressbar=False, regions=regions)
    return proj, cfg


class TestFlirt(unittest.TestCase):
    def test_amd64_elf_static_libc_ubuntu_2004(self):
        # _IO_file_open is named by the module anchored at 0x4140a0 (the start of fileops.o) at offset 0x1c20;
        # __mempcpy_chk_avx512_no_vzeroupper is the first function of its own module
        proj, cfg = load_static_libc([(0x4140A0, 0x414120), (0x415CC0, 0x415DB0), (0x436980, 0x4369A0)])
        proj.analyses.Flirt(STATIC_LIBC_SIG)

        assert cfg.functions[0x415CC0].name == "_IO_file_open"
        assert cfg.functions[0x415CC0].is_default_name is False
        assert cfg.functions[0x415CC0].from_signature == "flirt"
        assert cfg.functions[0x436980].name == "__mempcpy_chk_avx512_no_vzeroupper"
        assert cfg.functions[0x436980].is_default_name is False
        assert cfg.functions[0x436980].from_signature == "flirt"

    def test_referenced_function_offsets_are_function_relative(self):
        # ___asprintf and __fprintf are byte-identical; their signature modules differ only by the function each one
        # calls at offset 0x96 from its start. With the callees named, the signature tells the two apart.
        proj, cfg = load_static_libc([(0x410BD0, 0x410C90), (0x45E2D0, 0x45E390)])
        cfg.functions[0x4139C0].name = "__vasprintf_internal"
        cfg.functions[0x4613C0].name = "__vfprintf_internal"
        proj.analyses.Flirt(STATIC_LIBC_SIG)

        assert cfg.functions[0x410BD0].name == "___asprintf"
        assert cfg.functions[0x45E2D0].name == "__fprintf"

    def test_referenced_functions_recognized_in_the_same_run(self):
        # the callees that tell ___asprintf and __fprintf apart, __vasprintf_internal and __vfprintf_internal, are
        # themselves recognized by the same signature, so nothing needs to be named beforehand.
        # __vfprintf_internal (0x4613c0) is named by the module anchored at 0x45e390, which the third region covers.
        proj, cfg = load_static_libc([(0x410BD0, 0x410C90), (0x4139C0, 0x413B60), (0x45E2D0, 0x45E3E0)])
        proj.analyses.Flirt(STATIC_LIBC_SIG)

        assert cfg.functions[0x4139C0].name == "__vasprintf_internal"
        assert cfg.functions[0x4613C0].name == "__vfprintf_internal"
        assert cfg.functions[0x410BD0].name == "___asprintf"
        assert cfg.functions[0x45E2D0].name == "__fprintf"

    def test_referenced_function_reached_by_tail_jump(self):
        # _setjmp is "endbr64; xor esi, esi; jmp __sigsetjmp", and its signature module's only reference,
        # ^0007 __sigsetjmp, is the operand of that tail jump rather than of a call.
        # _dl_catch_exception (0x47e830) calls __sigsetjmp, which is what makes it a function of its own rather than
        # a continuation of _setjmp.
        proj, cfg = load_static_libc([(0x40F3F0, 0x40F400), (0x45C2E0, 0x45C350), (0x47E830, 0x47E950)])
        assert cfg.functions[0x40F3F0].jumpout_targets() == [(0x40F3F0, 0x45C2E0, 0x40F3F6)]
        proj.analyses.Flirt(STATIC_LIBC_SIG)

        assert cfg.functions[0x45C2E0].name == "__sigsetjmp"
        assert cfg.functions[0x40F3F0].name == "_setjmp"

    def test_armhf_elf_static_using_armel_libc(self):
        binary_path = os.path.join(bin_location, "tests", "armhf", "amp_challenge_07.gcc")
        proj = angr.Project(binary_path, auto_load_libs=False, load_debug_info=False)
        proj.analyses.CFGFast(show_progressbar=False, regions=[(0x1004C9, 0x1007A9)])
        flirt_path = os.path.join(bin_location, "tests", "armhf", "debian_10.3_libc.sig")
        flirt = proj.analyses.Flirt(flirt_path)

        assert len(flirt.matched_suggestions) == 1

        assert proj.kb.functions[0x1004C9].name == "strstr"
        assert proj.kb.functions[0x1004C9].prototype is not None
        assert proj.kb.functions[0x1004C9].calling_convention is not None

    def test_flirt_sig_loading(self):
        flirt_path = os.path.join(bin_location, "tests", "armhf", "debian_10.3_libc.sig")
        r = angr.flirt.load_signature(flirt_path)
        assert r is not None
        _, sig = r
        assert sig.sig_name == "libc"

        # with meta file
        meta_path = os.path.join(bin_location, "tests", "armhf", "debian_10.3_libc.meta")
        r = angr.flirt.load_signature(flirt_path, meta_path=meta_path)
        assert r is not None
        _, sig = r
        assert sig.arch == "armel"
        assert sig.os_name == "debian"


if __name__ == "__main__":
    unittest.main()
