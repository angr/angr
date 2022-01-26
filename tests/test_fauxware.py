# pylint: disable=missing-class-docstring,disable=no-self-use
import gc
import os
import pickle
import logging
import sys
import unittest

import angr
from common import slow_test

from angr.state_plugins.history import HistoryIter

l = logging.getLogger("angr.tests")
test_location = os.path.join(
    os.path.dirname(os.path.realpath(__file__)), "..", "..", "binaries", "tests"
)

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
    "x86_64": [0x400742, b"\xd4&\xb0[\x41", lambda s: s.registers.store("rdx", 8)],
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
    def run_fauxware(self, arch):
        p = angr.Project(
            os.path.join(test_location, arch, "fauxware"), auto_load_libs=False
        )
        results = p.factory.simulation_manager().explore(
            find=target_addrs[arch], avoid=avoid_addrs[arch]
        )
        stdin = results.found[0].posix.dumps(0)
        assert b"\x00\x00\x00\x00\x00\x00\x00\x00\x00SOSNEAKY\x00" == stdin

        # test the divergence detection
        ancestor = results.found[0].history.closest_common_ancestor(
            (results.avoid + results.active)[0].history
        )
        divergent_point = list(HistoryIter(results.found[0].history, end=ancestor))[0]
        # p.factory.block(divergent_point.addr).pp()
        assert divergent_point.recent_bbl_addrs[0] == divergences[arch]

    def run_pickling(self, arch):
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
    def run_fastmem(self, arch):
        p = angr.Project(os.path.join(test_location, arch, "fauxware"), auto_load_libs=False)
        p.analyses.CongruencyCheck(throw=True).set_state_options(right_add_options={"FAST_REGISTERS"}).run()

    def run_nodecode(self, arch):
        p = angr.Project(os.path.join(test_location, arch, "fauxware"), auto_load_libs=False)

        # screw up the instructions and make sure the test fails with nodecode
        for i, c in enumerate(corrupt_addrs[arch][1]):
            p.loader.memory[corrupt_addrs[arch][0] + i] = c
        boned = p.factory.simulation_manager().explore(
            find=target_addrs[arch], avoid=avoid_addrs[arch]
        )
        assert len(boned.errored) >= 1
        assert isinstance(boned.errored[0].error, angr.SimIRSBNoDecodeError)
        assert boned.errored[0].state.addr == corrupt_addrs[arch][0]

        # hook the instructions with the emulated stuff
        p.hook(
            corrupt_addrs[arch][0],
            corrupt_addrs[arch][2],
            length=len(corrupt_addrs[arch][1]),
        )
        results = p.factory.simulation_manager().explore(
            find=target_addrs[arch], avoid=avoid_addrs[arch]
        )
        stdin = results.found[0].posix.dumps(0)
        assert b"\x00\x00\x00\x00\x00\x00\x00\x00\x00SOSNEAKY\x00" == stdin

    def run_merge(self, arch):
        p = angr.Project(os.path.join(test_location, arch, "fauxware"), auto_load_libs=False)
        pg = p.factory.simulation_manager()
        pg.explore()

        # release the unmergable data
        for s in pg.deadended:
            s.release_plugin("fs")
            if 3 in s.posix.fd:
                s.posix.close(3)

        pg.merge(stash="deadended", merge_key=lambda s: s.addr)

        path = pg.deadended[
            [b"Welcome" in s for s in pg.mp_deadended.posix.dumps(1).mp_items].index(True)
        ]
        yes, no = path.history.merge_conditions
        inp = path.posix.stdin.content[2][0]  # content of second packet
        try:
            assert b"SOSNEAKY" in path.solver.eval(
                inp, cast_to=bytes, extra_constraints=(yes,)
            )
            assert b"SOSNEAKY" not in path.solver.eval(
                inp, cast_to=bytes, extra_constraints=(no,)
            )
        except AssertionError:
            yes, no = no, yes
            assert b"SOSNEAKY" in path.solver.eval(
                inp, cast_to=bytes, extra_constraints=(yes,)
            )
            assert b"SOSNEAKY" not in path.solver.eval(
                inp, cast_to=bytes, extra_constraints=(no,)
            )

    def test_merge(self):
        for arch in target_addrs:
            yield self.run_merge, arch

    def test_fauxware(self):
        for arch in target_addrs:
            yield self.run_fauxware, arch

    def test_pickling(self):
        for arch in corrupt_addrs:
            yield self.run_pickling, arch

    @slow_test
    def test_fastmem(self):
        # for arch in target_addrs:
        #   yield run_fastmem, arch
        # TODO: add support for comparing flags of other architectures
        # yield run_fastmem, "i386"
        yield self.run_fastmem, "x86_64"
        # yield run_fastmem, "ppc"
        # yield run_fastmem, "mips"

    def test_nodecode(self):
        for arch in corrupt_addrs:
            yield self.run_nodecode, arch


if __name__ == "__main__":
    unittest.main()
