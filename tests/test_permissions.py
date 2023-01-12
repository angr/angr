import angr

import logging

l = logging.getLogger("angr_tests")

import os

test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "binaries", "tests")


def test_nx():
    nx_amd64 = angr.Project(os.path.join(test_location, "x86_64", "memmove"), auto_load_libs=False)
    es = nx_amd64.factory.entry_state()

    # .text should be PROT_READ|PROT_EXEC
    assert es.solver.eval(es.memory.permissions(nx_amd64.entry)) == 5

    # load stack to initialize page
    es.memory.load(es.regs.sp, 4)

    # stack should be PROT_READ|PROT_WRITE
    assert es.solver.eval(es.memory.permissions(es.regs.sp)) == 3


if __name__ == "__main__":
    test_nx()
