import os
import unittest

import angr

test_location = os.path.join(os.path.dirname(os.path.realpath(str(__file__))), "..", "..", "binaries", "tests")

arch_data = {  # (steps, [hit addrs], finished)
    "x86_64": (330, (0x1021C20, 0x1021980, 0x1021BE0, 0x4004B0, 0x400440, 0x400570), True),
    "i386": (
        425,
        (0x90198E0, 0x90195C0, 0x9019630, 0x90198A0, 0x8048370, 0x80482F8, 0x8048440, 0x804846D, 0x8048518),
        True,
    ),
    "ppc": (381, (0x11022F50, 0x11022EB0, 0x10000340, 0x100002E8, 0x1000053C, 0x1000063C), True),
    "ppc64": (372, (0x11047490, 0x100003FC, 0x10000368, 0x10000654, 0x10000770), True),
    "mips": (363, (0x1016F20, 0x400500, 0x400470, 0x400640, 0x400750), True),
    "mips64": (390, (0x12103B828, 0x120000870, 0x1200007E0, 0x120000A80, 0x120000B68), True),
    "armel": (370, (0x10154B8, 0x1108244, 0x83A8, 0x8348, 0x84B0, 0x84E4, 0x85E8), True),
    "aarch64": (370, (0x1020B04, 0x400430, 0x4003B8, 0x400538, 0x400570, 0x40062C), True),
}


# pylint: disable=missing-class-docstring
# pylint: disable=no-self-use
class TestAccuracy(unittest.TestCase):
    def _emulate(self, arch, binary, use_sim_procs, steps, hit_addrs, finished):
        # auto_load_libs can't be disabled as the test takes longer time to execute
        p = angr.Project(
            os.path.join(test_location, arch, binary),
            use_sim_procedures=use_sim_procs,
            rebase_granularity=0x1000000,
            load_debug_info=False,
            auto_load_libs=True,
        )
        state = p.factory.full_init_state(
            args=["./test_arrays"],
            add_options={
                angr.options.STRICT_PAGE_ACCESS,
                angr.options.ENABLE_NX,
                angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
                angr.options.USE_SYSTEM_TIMES,
            },
        )

        pg = p.factory.simulation_manager(state, resilience=True)
        pg2 = pg.run(until=lambda lpg: len(lpg.active) != 1)

        is_finished = False
        if len(pg2.active) > 0:
            state = pg2.active[0]
        elif len(pg2.deadended) > 0:
            state = pg2.deadended[0]
            is_finished = True
        elif len(pg2.errored) > 0:
            state = pg2.errored[0].state  # ErroredState object!
        else:
            raise ValueError("The result does not contain a state we can use for this test?")

        assert state.history.depth >= steps

        # this is some wonky control flow that asserts that the items in hit_addrs appear in the state in order.
        trace = state.history.bbl_addrs.hardcopy
        reqs = list(hit_addrs)
        while len(reqs) > 0:
            req = reqs.pop(0)
            while True:
                assert len(trace) > 0
                trace_head = trace.pop(0)
                if trace_head == req:
                    break
                assert trace_head not in reqs

        if finished:
            assert is_finished

    def test_windows(self):
        self._emulate(
            "i386", "test_arrays.exe", True, 41, [], False
        )  # blocked on GetLastError or possibly dynamic loading

    def test_x86_64(self):
        steps, hit_addrs, finished = arch_data["x86_64"]
        self._emulate("x86_64", "test_arrays", False, steps, hit_addrs, finished)

    def test_i386(self):
        steps, hit_addrs, finished = arch_data["i386"]
        self._emulate("i386", "test_arrays", False, steps, hit_addrs, finished)

    def test_ppc(self):
        steps, hit_addrs, finished = arch_data["ppc"]
        self._emulate("ppc", "test_arrays", False, steps, hit_addrs, finished)

    def test_ppc64(self):
        steps, hit_addrs, finished = arch_data["ppc64"]
        self._emulate("ppc64", "test_arrays", False, steps, hit_addrs, finished)

    def test_mips(self):
        steps, hit_addrs, finished = arch_data["mips"]
        self._emulate("mips", "test_arrays", False, steps, hit_addrs, finished)

    def test_mips64(self):
        steps, hit_addrs, finished = arch_data["mips64"]
        self._emulate("mips64", "test_arrays", False, steps, hit_addrs, finished)

    def test_armel(self):
        steps, hit_addrs, finished = arch_data["armel"]
        self._emulate("armel", "test_arrays", False, steps, hit_addrs, finished)

    def test_aarch64(self):
        steps, hit_addrs, finished = arch_data["aarch64"]
        self._emulate("aarch64", "test_arrays", False, steps, hit_addrs, finished)

    def test_locale(self):
        # auto_load_libs can't be disabled as the test takes longer time to execute
        p = angr.Project(os.path.join(test_location, "i386", "isalnum"), use_sim_procedures=False, auto_load_libs=True)
        state = p.factory.full_init_state(args=["./isalnum"], add_options={angr.options.STRICT_PAGE_ACCESS})
        pg = p.factory.simulation_manager(state)
        pg2 = pg.run(
            until=lambda lpg: len(lpg.active) != 1, step_func=lambda lpg: lpg if len(lpg.active) == 1 else lpg.prune()
        )
        assert len(pg2.active) == 0
        assert len(pg2.deadended) == 1
        assert pg2.deadended[0].history.events[-1].type == "terminate"
        assert pg2.deadended[0].history.events[-1].objects["exit_code"]._model_concrete.value == 0


if __name__ == "__main__":
    # emulate('armel', 'test_arrays', False, *arch_data['armel'])
    # import sys; sys.exit()
    unittest.main()
