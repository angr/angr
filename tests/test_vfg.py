import time
import os
import logging
import unittest
import claripy

import angr

l = logging.getLogger("angr_tests")

test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "binaries", "tests")

vfg_buffer_overflow_addresses = {"x86_64": 0x40055C}

vfg_1_addresses = {
    "x86_64": {
        0x40071D,  # main
        0x400510,  # _puts
        0x40073E,  # main
        0x400530,  # _read
        0x400754,  # main
        0x40076A,  # main
        0x400774,  # main
        0x40078A,  # main
        0x4007A0,  # main
        0x400664,  # authenticate
        0x400550,  # _strcmp
        0x40068E,  # authenticate
        0x400699,  # authenticate
        0x400560,  # _open
        0x4006AF,  # authenticate
        0x4006C8,  # authenticate
        0x4006DB,  # authenticate
        0x400692,  # authenticate
        0x4006DF,  # authenticate
        0x4006E6,  # authenticate
        0x4006EB,  # authenticate
        0x4007BD,  # main
        0x4006ED,  # accepted
        0x4006FB,  # accepted
        0x4007C7,  # main
        0x4007C9,  # main
        0x4006FD,  # rejected
        0x400520,  # _printf
        0x400713,  # rejected
        0x400570,  # _exit
    }
}


class TestVfg(unittest.TestCase):
    def _run_vfg_buffer_overflow(self, arch):
        # pylint: disable=no-member
        proj = angr.Project(
            os.path.join(test_location, arch, "basic_buffer_overflows"),
            use_sim_procedures=True,
            default_analysis_mode="symbolic",
            auto_load_libs=False,
        )

        cfg = proj.analyses.CFGEmulated(context_sensitivity_level=1)

        # For this test case, OPTIMIZE_IR does not work due to the way we are widening the states: an index variable
        # directly goes to 0xffffffff, and when OPTIMIZE_IR is used, it does a signed comparison with 0x27, which
        # eventually leads to the merged index variable covers all negative numbers and [0, 27]. This analysis result is
        # correct but not accurate, and we suffer from it in this test case.
        # The ultimate solution is to widen more carefully, or implement lookahead widening support.
        # TODO: Solve this issue later

        start = time.time()
        function_start = vfg_buffer_overflow_addresses[arch]
        vfg = proj.analyses.VFG(
            cfg,
            function_start=function_start,
            context_sensitivity_level=2,
            interfunction_level=4,
            remove_options={angr.options.OPTIMIZE_IR},
        )
        end = time.time()
        duration = end - start

        l.info("VFG generation done in %f seconds.", duration)

        # TODO: These are very weak conditions. Make them stronger!
        assert len(vfg.final_states) > 0
        states = vfg.final_states
        assert len(states) == 2
        stack_check_fail = proj._extern_obj.get_pseudo_addr("symbol hook: __stack_chk_fail")
        assert {s.solver.eval_one(s.ip) for s in states} == {
            stack_check_fail,
            0x4005B4,
        }

        state = [s for s in states if s.solver.eval_one(s.ip) == 0x4005B4][0]
        assert claripy.backends.vsa.is_true(state.stack_read(12, 4) >= 0x28)

    def broken_vfg_buffer_overflow(self):
        # Test for running VFG on a single function
        self._run_vfg_buffer_overflow("x86_64")

    #
    # VFG test case 0
    #

    def test_vfg_0(self):
        self._run_vfg_0("x86_64")

    def _run_vfg_0(self, arch):
        proj = angr.Project(
            os.path.join(test_location, arch, "vfg_0"),
            load_options={"auto_load_libs": False},
        )

        cfg = proj.analyses.CFG(normalize=True)
        main = cfg.functions.function(name="main")
        vfg = proj.analyses.VFG(
            cfg,
            start=main.addr,
            context_sensitivity_level=1,
            interfunction_level=3,
            record_function_final_states=True,
            max_iterations=80,
        )

        function_final_states = vfg._function_final_states
        assert main.addr in function_final_states

        final_state_main = next(iter(function_final_states[main.addr].values()))
        stdout = final_state_main.posix.dumps(1)

        assert stdout[:6] == b"i = 64"
        # the following does not work without affine relation analysis
        # assert stdout == "i = 64

    #
    # VFG test case 1
    #

    def _run_vfg_1(self, arch):
        proj = angr.Project(
            os.path.join(test_location, arch, "fauxware"), use_sim_procedures=True, auto_load_libs=False
        )

        cfg = proj.analyses.CFGEmulated()
        vfg = proj.analyses.VFG(
            cfg,
            start=0x40071D,
            context_sensitivity_level=10,
            interfunction_level=10,
            record_function_final_states=True,
        )

        all_block_addresses = {n.addr for n in vfg.graph.nodes()}
        assert vfg_1_addresses[arch].issubset(all_block_addresses)

        # return value for functions

        # function authenticate has only two possible return values: 0 and 1
        authenticate = cfg.functions.function(name="authenticate")
        assert authenticate.addr in vfg.function_final_states
        authenticate_final_states = vfg.function_final_states[authenticate.addr]
        assert len(authenticate_final_states) == 1
        authenticate_final_state = next(iter(authenticate_final_states.values()))
        assert authenticate_final_state is not None
        assert authenticate_final_state.solver.eval_upto(authenticate_final_state.regs.rax, 3) == [0, 1]

        # optimal execution tests
        # - the basic block after returning from `authenticate` should only be executed once
        assert vfg._execution_counter[0x4007B3] == 1
        # - the last basic block in `authenticate` should only be executed once (on a non-normalized CFG)
        assert vfg._execution_counter[0x4006EB] == 1

    def test_vfg_1(self):
        # Test the code coverage of VFG
        self._run_vfg_1("x86_64")

    def test_vfg_resolving_indirect_calls(self):
        # resolving indirect calls provided via a statically allocated list of function addresses
        # the test binary is contributed by Luke Serné on angr Slack
        proj = angr.Project(
            os.path.join(test_location, "aarch64", "func-chain-aarch64"),
            auto_load_libs=False,
        )
        cfg = proj.analyses.CFG(normalize=True)
        vfg = proj.analyses.VFG(
            cfg,
            start=cfg.kb.functions["main"].addr,
            context_sensitivity_level=1,
            interfunction_level=1,
            record_function_final_states=True,
        )

        # find the node with indirect call exits
        expected_indirect_call_targets = {
            (0x400808, 0x400754),  # init_0
            (0x400808, 0x400770),  # init_1
            (0x400808, 0x400790),  # init_2
        }
        indirect_call_targets = set()
        for block_addr in cfg.kb.functions["main"].block_addrs_set:
            cfg_node = cfg.get_any_node(block_addr)
            succs_and_jumpkinds = cfg_node.successors_and_jumpkinds()
            if len(succs_and_jumpkinds) == 1 and succs_and_jumpkinds[0][1] == "Ijk_Call":
                # does it lead to an UnresolvedCall?
                if succs_and_jumpkinds[0][0].name == "UnresolvableCallTarget":
                    # found it!
                    for vfg_node in vfg.get_all_nodes(cfg_node.addr):
                        for successor_state in vfg_node.final_states:
                            if successor_state.history.jumpkind == "Ijk_Call":
                                indirect_call_targets.add((cfg_node.addr, successor_state.addr))

        assert expected_indirect_call_targets == indirect_call_targets


if __name__ == "__main__":
    unittest.main()
