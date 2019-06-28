import angr
import claripy
import nose

from angr.state_plugins.inspect import BP_BEFORE, BP_AFTER, BP_BOTH

test_counter = 0

def run_check(state):
    global test_counter
    test_counter += 1

def inspect_any_arg(check_arg, pass_arg, *fail_args):
    global test_counter
    test_counter = 0

    state = angr.SimState(arch="AMD64")

    state.inspect.make_breakpoint("exit", when=BP_BEFORE, exit_jumpkind=check_arg, action=run_check)

    state._inspect("exit", BP_BEFORE, exit_jumpkind=pass_arg)
    nose.tools.assert_equal(test_counter, 1)

    for fail_arg in fail_args:
        state._inspect("exit", BP_AFTER, exit_jumpkind=fail_arg)
        nose.tools.assert_equal(test_counter, 1)


def test_inspect_primitive_arg():
    fail_arg = claripy.BVV("0x1")
    inspect_any_arg(True, True, False)
    inspect_any_arg(1.0, 1.0, 2.0, 3.0)
    inspect_any_arg("foo", "foo", "bar", "baz")

def test_inspect_ast_arg():
    pass_arg = claripy.BVV("0x1")
    fail_arg = claripy.BVV("0x2")
    inspect_any_arg(pass_arg, pass_arg, fail_arg)
    inspect_any_arg(pass_arg, pass_arg, True)
    inspect_any_arg(pass_arg, pass_arg, 1)
    inspect_any_arg(pass_arg, pass_arg, "0x1")

if __name__ == "__main__":
    test_inspect_primitive_arg()
    test_inspect_ast_arg()
