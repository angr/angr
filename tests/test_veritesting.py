import os
import unittest
import logging

import angr
import claripy


l = logging.getLogger("angr_tests.veritesting")

location = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "binaries", "tests")

addresses_veritesting_a = {"x86_64": 0x400674}

addresses_veritesting_b = {"x86_64": 0x4006AF}


class TestVeritesting(unittest.TestCase):
    def _run_veritesting_a(self, arch):
        # TODO: Added timeout control, since a failed state merging will result in running for a long time

        # logging.getLogger('angr.analyses.sse').setLevel(logging.DEBUG)

        proj = angr.Project(
            os.path.join(location, arch, "veritesting_a"),
            load_options={"auto_load_libs": False},
            use_sim_procedures=True,
        )
        ex = proj.factory.simulation_manager(veritesting=True)
        ex.explore(find=addresses_veritesting_a[arch])
        assert len(ex.found) != 0

        # Make sure the input makes sense
        for f in ex.found:
            input_str = f.plugins["posix"].dumps(0)
            assert input_str.count(b"B") == 10

        # make sure the solution is actually found by veritesting
        assert len(ex.found) == 1
        state = ex.found[0]
        for var in state.solver._solver.variables:
            assert "state_merge" not in var

    def _run_veritesting_b(self, arch):
        # logging.getLogger('angr.analyses.sse').setLevel(logging.DEBUG)

        proj = angr.Project(
            os.path.join(location, arch, "veritesting_b"),
            load_options={"auto_load_libs": False},
            use_sim_procedures=True,
        )
        ex = proj.factory.simulation_manager()
        ex.use_technique(angr.exploration_techniques.Veritesting(enable_function_inlining=True))
        ex.explore(find=addresses_veritesting_b[arch])
        assert len(ex.found) != 0

        # Make sure the input makes sense
        for f in ex.found:
            input_str = f.plugins["posix"].dumps(0)
            assert input_str.count(b"B") == 35

        # make sure the solution is actually found by veritesting
        assert len(ex.found) == 1
        state = ex.found[0]
        for var in state.solver._solver.variables:
            assert "state_merge" not in var

    def _run_veritesting_skm(self, arch):
        proj = angr.Project(os.path.join(location, arch, "veritesting_skm"))

        # start the analysis after the call to lexer_read_line
        state = proj.factory.blank_state(addr=0x4024AE, remove_options={angr.sim_options.UNICORN})

        # set up the structures for the user_input
        byte = claripy.BVS("user_byte", 8)  # Symbolic variable for user_input
        SPACE = claripy.Or((byte == 32), (byte == 9))
        NUM = claripy.And(byte >= 48, byte <= 57)
        NL = byte == 10
        MULOP = claripy.Or(byte == 42, byte == 47)
        ADDOP = claripy.Or(byte == 43, byte == 45)
        constraint = claripy.Or(NUM, ADDOP, MULOP, NL, SPACE)
        state.add_constraints(constraint)

        # set up memory
        LINEPTR = 0xCAFEBABE  # fake addr
        state.memory.store(LINEPTR, byte)
        state.memory.store(LINEPTR + 1, 0)  # NULL term the string!

        # stack
        state.regs.rax = LINEPTR
        state.regs.rbp = 0xDEADBEEF  # STACK
        state.regs.rdi = LINEPTR  # 64 bit Intel calling convention - RDI gets arg0

        simgr = proj.factory.simgr(state, veritesting=True)
        is_successful = 0x402517
        should_abort = 0x402521
        simgr.explore(find=is_successful, avoid=should_abort)
        assert simgr.found

    def test_veritesting_a(self):
        # This is the most basic test
        self._run_veritesting_a("x86_64")

    def test_veritesting_b(self):
        # Advanced stuff - it tests for the ability to inline simple functions
        # as well as simple syscalls like read/write
        self._run_veritesting_b("x86_64")

    def test_veritesting_skm(self):
        # More advanced stuff, this binary will do double state merging,
        # which requires merged states to be correct
        self._run_veritesting_skm("x86_64")


if __name__ == "__main__":
    unittest.main()
