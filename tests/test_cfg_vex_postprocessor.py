
import os

import angr

test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', '..', 'binaries', 'tests')


def test_issue_1172():

    path = os.path.join(test_location, "x86_64", "cfg_issue_1172")
    p = angr.Project(path, auto_load_libs=False)

    # it should not crash
    _ = p.analyses.CFG()


if __name__ == "__main__":
    test_issue_1172()
