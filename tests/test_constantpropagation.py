# pylint: disable=missing-class-docstring,disable=no-self-use
import os
import unittest

import angr

test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "binaries", "tests")


class TestConstantpropagation(unittest.TestCase):
    def test_libc_x86(self):
        # disabling auto_load_libs increases the execution time.
        p = angr.Project(os.path.join(test_location, "i386", "libc-2.27-3ubuntu1.so.6"), auto_load_libs=True)
        dl_addr = p.loader.find_symbol("_dl_addr").rebased_addr
        cfg = p.analyses.CFGFast(regions=[(dl_addr, dl_addr + 4096)])
        func = cfg.functions["_dl_addr"]

        rtld_global_sym = p.loader.find_symbol("_rtld_global")
        assert rtld_global_sym is not None
        _rtld_global_addr = rtld_global_sym.rebased_addr

        base_addr = 0x998F000
        state = p.factory.blank_state()
        for addr in range(0, 0 + 0x1000, p.arch.bytes):
            state.memory.store(
                _rtld_global_addr + addr, base_addr + addr, size=p.arch.bytes, endness=p.arch.memory_endness
            )

        prop = p.analyses.Propagator(func=func, base_state=state)
        # import pprint
        # pprint.pprint(prop.replacements)
        assert len(prop.replacements) > 0

    def test_lwip_udpecho_bm(self):
        bin_path = os.path.join(test_location, "armel", "lwip_udpecho_bm.elf")
        p = angr.Project(bin_path, auto_load_libs=False)
        cfg = p.analyses.CFG(data_references=True)

        func = cfg.functions[0x23C9]
        state = p.factory.blank_state()
        prop = p.analyses.Propagator(func=func, base_state=state)

        assert len(prop.replacements) > 0


if __name__ == "__main__":
    unittest.main()
