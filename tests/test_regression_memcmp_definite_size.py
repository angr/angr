import os


import angr
import claripy as cp

test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "binaries", "tests")


def regression_test_memcmp_strlen_simprocedure_interaction():
    # import logging
    # logging.getLogger('angr.manager').setLevel(logging.DEBUG)

    bin_path = os.path.join(test_location, "i386", "cpp_regression_test_ch25")
    p = angr.Project(bin_path, auto_load_libs=True)  # this binary requires the loading of libstdc++.so.6
    argv1 = cp.Concat(*[cp.BVS("argv%d" % i, 8) for i in range(48)])

    state = p.factory.full_init_state(args=[bin_path, argv1], add_options=angr.sim_options.unicorn)

    sm = p.factory.simulation_manager(state)
    x = sm.explore(find=0x8048B9B, num_find=3)

    assert len(x.found) == 1
    for state in x.found:
        solution = state.solver.eval_one(argv1, cast_to=bytes).strip(b"\x00")
        assert solution == b"Here_you_have_to_understand_a_little_C++_stuffs"


if __name__ == "__main__":
    regression_test_memcmp_strlen_simprocedure_interaction()
