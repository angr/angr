import nose
import angr

import logging
l = logging.getLogger("angr_tests")

import os
test_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../../binaries/tests'))
private_test_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../../binaries-private/'))

def test_nx():
    nx_amd64 = angr.Project(test_location + "/x86_64/memmove")
    es = nx_amd64.factory.entry_state()

    # .text should be PROT_READ|PROT_EXEC
    nose.tools.assert_equal(es.se.any_int(es.memory.permissions(nx_amd64.entry)), 5)

    # load stack to initialize page
    es.memory.load(es.regs.sp, 4)

    # stack should be PROT_READ|PROT_WRITE
    nose.tools.assert_equal(es.se.any_int(es.memory.permissions(es.regs.sp)), 3)

def test_no_nx():

    no_nx_i386 = angr.Project(private_test_location + "/cgc_scored_event_1/cgc/0b32aa01_01")
    es = no_nx_i386.factory.entry_state()

    nose.tools.assert_equal(es.se.any_int(es.memory.permissions(no_nx_i386.entry)), 5)

    # load stack to initialize page
    es.memory.load(es.regs.sp, 4)

    # stack should be PROT_READ|PROT_WRITE|PROT_EXEC
    nose.tools.assert_equal(es.se.any_int(es.memory.permissions(es.regs.sp)), 7)

if __name__ == "__main__":
    test_nx()
    test_no_nx()
