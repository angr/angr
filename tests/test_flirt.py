# pylint: disable=missing-class-docstring,disable=no-self-use
import os.path
import unittest

from common import bin_location
import angr


class TestFlirt(unittest.TestCase):
    def test_amd64_elf_static_libc_ubuntu_2004(self):
        binary_path = os.path.join(bin_location, "tests", "x86_64", "elf_with_static_libc_ubuntu_2004_stripped")
        proj = angr.Project(binary_path, auto_load_libs=False, load_debug_info=False)
        cfg = proj.analyses.CFGFast(show_progressbar=False)  # , detect_tail_calls=True)
        flirt_path = os.path.join(bin_location, "tests", "x86_64", "libc_ubuntu_2004.sig")
        proj.analyses.Flirt(flirt_path)

        assert cfg.functions[0x415CC0].name == "_IO_file_open"
        assert cfg.functions[0x415CC0].is_default_name is False
        assert cfg.functions[0x415CC0].from_signature == "flirt"
        assert cfg.functions[0x436980].name == "__mempcpy_chk_avx512_no_vzeroupper"
        assert cfg.functions[0x436980].is_default_name is False
        assert cfg.functions[0x436980].from_signature == "flirt"

    def test_armhf_elf_static_using_armel_libc(self):
        binary_path = os.path.join(bin_location, "tests", "armhf", "amp_challenge_07.gcc")
        proj = angr.Project(binary_path, auto_load_libs=False, load_debug_info=False)
        proj.analyses.CFGFast(show_progressbar=False)
        flirt_path = os.path.join(bin_location, "tests", "armhf", "debian_10.3_libc.sig")
        flirt = proj.analyses.Flirt(flirt_path)

        assert len(flirt.matched_suggestions) == 1

        assert proj.kb.functions[0x1004C9].name == "strstr"
        assert proj.kb.functions[0x1004C9].prototype is not None
        assert proj.kb.functions[0x1004C9].calling_convention is not None

        assert proj.kb.functions[0xF38D9].name == "__printf"
        assert proj.kb.functions[0xF38D9].prototype is not None
        assert proj.kb.functions[0xF38D9].calling_convention is not None


if __name__ == "__main__":
    unittest.main()
