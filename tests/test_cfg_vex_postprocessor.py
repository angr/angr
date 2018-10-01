
import os

import nose.tools

import angr


def test_issue_1172():

    path = os.path.join("..", "..", "binaries", "tests", "x86_64", "cfg_issue_1172")
    p = angr.Project(path, auto_load_libs=False)

    # it should not crash
    cfg = p.analyses.CFG()


if __name__ == "__main__":
    test_issue_1172()
