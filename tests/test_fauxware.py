# pylint: disable=missing-class-docstring,no-self-use
import gc
import logging
import os
import pickle
import unittest

from common import slow_test

import angr
from angr.state_plugins.history import HistoryIter


l = logging.getLogger("angr.tests")
test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "binaries", "tests")

target_addrs = {
    "i386": [0x080485C9],
    "x86_64": [0x4006ED],
    "ppc": [0x1000060C],
    "armel": [0x85F0],
    "android/arm": [0x4004CC],
    "mips": [0x4009FC],
}

avoid_addrs = {
    "i386": [0x080485DD, 0x08048564],
    "x86_64": [0x4006AA, 0x4006FD],
    "ppc": [0x10000644, 0x1000059C],
    "armel": [0x86F8, 0x857C],
    "android/arm": [0x4004F0, 0x400470],
    "mips": [0x400A10, 0x400774],
}

corrupt_addrs = {
    "i386": [0x80486B6, b"bO\xcc", lambda s: s.memory.store(s.regs.esp, s.regs.eax)],
    "x86_64": [0x400742, b"\x0f\x0b\xb0[\x41", lambda s: s.registers.store("rdx", 8)],
    "ppc": [0x100006B8, b"\x05\xad\xc2\xea", lambda s: s.registers.store("r5", 8)],
    "armel": [0x8678, b"\xbdM\xec3", lambda s: s.registers.store("r2", 8)],
    "mips": [0x400918, b"[\xf8\x96@"[::-1], lambda s: s.registers.store("a2", 8)],
}

divergences = {
    "ppc": 0x10000588,
    "x86_64": 0x40068E,
    "i386": 0x8048559,
    "armel": 0x8568,
    "android/arm": 0x40045C,
    "mips": 0x40075C,
}


class TestFauxware(unittest.TestCase):
    def _run_fauxware(self, arch):
        p = angr.Project(os.path.join(test_location, arch, "fauxware"), auto_load_libs=False)
        results = p.factory.simulation_manager().explore(find=target_addrs[arch], avoid=avoid_addrs[arch])
        stdin = results.found[0].posix.dumps(0)
        assert b"\x00\x00\x00\x00\x00\x00\x00\x00\x00SOSNEAKY\x00" == stdin

        # test the divergence detection
        ancestor = results.found[0].history.closest_common_ancestor((results.avoid + results.active)[0].history)
        divergent_point = list(HistoryIter(results.found[0].history, end=ancestor))[0]
        # p.factory.block(divergent_point.addr).pp()
        assert divergent_point.recent_bbl_addrs[0] == divergences[arch]

    def _run_pickling(self, arch):
        p = angr.Project(os.path.join(test_location, arch, "fauxware"), auto_load_libs=False)
        pg = p.factory.simulation_manager().run(n=10)
        pickled = pickle.dumps(pg, pickle.HIGHEST_PROTOCOL)
        del p
        del pg
        gc.collect()
        pg = pickle.loads(pickled)

        pg.explore(find=target_addrs[arch], avoid=avoid_addrs[arch])
        stdin = pg.found[0].posix.dumps(0)
        assert b"\x00\x00\x00\x00\x00\x00\x00\x00\x00SOSNEAKY\x00" == stdin

    @slow_test
    def _run_fastmem(self, arch):
        p = angr.Project(os.path.join(test_location, arch, "fauxware"), auto_load_libs=False)
        p.analyses.CongruencyCheck(throw=True).set_state_options(right_add_options={"FAST_REGISTERS"}).run()

    def _run_nodecode(self, arch):
        p = angr.Project(os.path.join(test_location, arch, "fauxware"), auto_load_libs=False)

        # screw up the instructions and make sure the test fails with nodecode
        for i, c in enumerate(corrupt_addrs[arch][1]):
            p.loader.memory[corrupt_addrs[arch][0] + i] = c
        boned = p.factory.simulation_manager().explore(find=target_addrs[arch], avoid=avoid_addrs[arch])
        assert len(boned.errored) >= 1
        assert isinstance(boned.errored[0].error, angr.SimIRSBNoDecodeError)
        assert boned.errored[0].state.addr == corrupt_addrs[arch][0]

        # hook the instructions with the emulated stuff
        p.hook(
            corrupt_addrs[arch][0],
            corrupt_addrs[arch][2],
            length=len(corrupt_addrs[arch][1]),
        )
        results = p.factory.simulation_manager().explore(find=target_addrs[arch], avoid=avoid_addrs[arch])
        stdin = results.found[0].posix.dumps(0)
        assert b"\x00\x00\x00\x00\x00\x00\x00\x00\x00SOSNEAKY\x00" == stdin

    def _run_merge(self, arch):
        p = angr.Project(os.path.join(test_location, arch, "fauxware"), auto_load_libs=False)
        pg = p.factory.simulation_manager()
        pg.explore()

        # release the unmergable data
        for s in pg.deadended:
            s.release_plugin("fs")
            if 3 in s.posix.fd:
                s.posix.close(3)

        pg.merge(stash="deadended", merge_key=lambda s: s.addr)

        path = pg.deadended[[b"Welcome" in s for s in pg.mp_deadended.posix.dumps(1).mp_items].index(True)]
        yes, no = path.history.merge_conditions
        inp = path.posix.stdin.content[2][0]  # content of second packet
        try:
            assert b"SOSNEAKY" in path.solver.eval(inp, cast_to=bytes, extra_constraints=(yes,))
            assert b"SOSNEAKY" not in path.solver.eval(inp, cast_to=bytes, extra_constraints=(no,))
        except AssertionError:
            yes, no = no, yes
            assert b"SOSNEAKY" in path.solver.eval(inp, cast_to=bytes, extra_constraints=(yes,))
            assert b"SOSNEAKY" not in path.solver.eval(inp, cast_to=bytes, extra_constraints=(no,))

    def test_merge_i386(self):
        self._run_merge("i386")

    def test_merge_x86_64(self):
        self._run_merge("x86_64")

    def test_merge_ppc(self):
        self._run_merge("ppc")

    def test_merge_armel(self):
        self._run_merge("armel")

    def test_merge_android(self):
        self._run_merge("android/arm")

    def test_merge_mips(self):
        self._run_merge("mips")

    def test_fauxware_i386(self):
        self._run_fauxware("i386")

    def test_fauxware_x86_64(self):
        self._run_fauxware("x86_64")

    def test_fauxware_ppc(self):
        self._run_fauxware("ppc")

    def test_fauxware_armel(self):
        self._run_fauxware("armel")

    def test_fauxware_android(self):
        self._run_fauxware("android/arm")

    def test_fauxware_mips(self):
        self._run_fauxware("mips")

    def test_pickling_i386(self):
        self._run_pickling("i386")

    def test_pickling_x86_64(self):
        self._run_pickling("x86_64")

    def test_pickling_ppc(self):
        self._run_pickling("ppc")

    def test_pickling_armel(self):
        self._run_pickling("armel")

    def test_pickling_mips(self):
        self._run_pickling("mips")

    @slow_test
    def test_fastmen(self):
        self._run_fastmem("x86_64")

    def test_nodecode_i386(self):
        self._run_nodecode("i386")

    def test_nodecode_x86_64(self):
        self._run_nodecode("x86_64")

    def test_nodecode_ppc(self):
        self._run_nodecode("ppc")

    def test_nodecode_armel(self):
        self._run_nodecode("armel")

    def test_nodecode_mips(self):
        self._run_nodecode("mips")


if __name__ == "__main__":
    unittest.main()
