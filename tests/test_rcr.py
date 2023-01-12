import os
import claripy
import angr


def test_rcr():
    p = angr.Project(
        os.path.join(os.path.dirname(__file__), "..", "..", "binaries", "tests", "i386", "rcr_test"),
        auto_load_libs=False,
    )
    result = p.factory.successors(p.factory.entry_state()).successors[0]
    assert claripy.is_true(result.regs.cl == 8)


if __name__ == "__main__":
    test_rcr()
