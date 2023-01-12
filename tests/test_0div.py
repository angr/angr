import os
import unittest

import angr

test_location = os.path.join(os.path.dirname(__file__), "..", "..", "binaries", "tests")


# pylint: disable=missing-class-docstring
# pylint: disable=no-self-use
class Test0Div(unittest.TestCase):
    def _run_0div(self, arch):
        # check that we run in unicorn up to the zero-div site, fall back, try again in angr, and error correctly.
        p = angr.Project(os.path.join(test_location, arch, "test_0div"), auto_load_libs=False)
        s = p.factory.entry_state(add_options=angr.options.unicorn)
        simgr = p.factory.simulation_manager(s)
        simgr.run(n=5)
        assert len(simgr.active) == 1
        simgr.step()
        assert len(simgr.errored) == 1
        assert isinstance(simgr.errored[0].error, angr.errors.SimZeroDivisionException)

    def test_0div_i386(self):
        self._run_0div("i386")

    def test_0div_x86_64(self):
        self._run_0div("x86_64")

    def test_symbolic_0div(self):
        p = angr.load_shellcode(b"X", arch="amd64")
        s = p.factory.blank_state()
        s.regs.rax = s.solver.BVS("rax", 64)
        s.regs.rcx = s.solver.BVS("rcx", 64)
        s.regs.rdx = s.solver.BVS("rdx", 64)

        s.options.add(angr.options.PRODUCE_ZERODIV_SUCCESSORS)
        successors = s.step(insn_bytes=b"\x48\xf7\xf1")  # div rcx
        assert len(successors.flat_successors) == 2

        s.options.discard(angr.options.PRODUCE_ZERODIV_SUCCESSORS)
        successors = s.step(insn_bytes=b"\x48\xf7\xf1")  # div rcx
        assert len(successors.flat_successors) == 1


if __name__ == "__main__":
    unittest.main()
