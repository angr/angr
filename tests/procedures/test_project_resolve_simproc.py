#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,line-too-long
__package__ = __package__ or "tests.procedures"  # pylint:disable=redefined-builtin

import os
import unittest

import angr

from ..common import bin_location


test_location = os.path.join(bin_location, "tests")
bina = os.path.join(test_location, "x86_64", "test_project_resolve_simproc")


# We voluntarily don't use SimProcedures for 'rand' and 'sleep' because we want
# to step into their lib code.
class TestProjectResolveSimProc(unittest.TestCase):
    def test_bina(self):
        # auto_load_libs can't be disabled as the testcase fails
        p = angr.Project(bina, exclude_sim_procedures_list=["rand", "sleep"], load_options={"auto_load_libs": True})

        # Make sure external functions are not replaced with a SimProcedure
        sleep_jmpslot = p.loader.main_object.jmprel["sleep"]
        rand_jmpslot = p.loader.main_object.jmprel["rand"]
        read_jmpslot = p.loader.main_object.jmprel["read"]

        sleep_addr = p.loader.memory.unpack_word(sleep_jmpslot.rebased_addr)
        rand_addr = p.loader.memory.unpack_word(rand_jmpslot.rebased_addr)
        read_addr = p.loader.memory.unpack_word(read_jmpslot.rebased_addr)

        libc_sleep_addr = p.loader.shared_objects["libc.so.6"].get_symbol("sleep").rebased_addr
        libc_rand_addr = p.loader.shared_objects["libc.so.6"].get_symbol("rand").rebased_addr

        assert sleep_addr == libc_sleep_addr
        assert rand_addr == libc_rand_addr
        assert p.is_hooked(read_addr)
        assert "read" in str(p._sim_procedures[read_addr])


if __name__ == "__main__":
    unittest.main()
