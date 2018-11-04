import nose
import angr

import os
location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../../binaries/tests'))


def test_engine_selector():
    p = angr.Project(location + '/x86_64/fauxware')
    s = p.factory.blank_state(addr=p.entry)

    # test if it works at all
    ss = p.factory.successors(s)
    nose.tools.assert_true(ss.processed)

    simproc_cls = angr.procedures.SIM_PROCEDURES["stubs"]["PathTerminator"]
    simproc = simproc_cls(p)

    # test insertion/removal
    p.engines.insert_engine(p.entry, simproc)
    nose.tools.assert_in(simproc, p.engines.list_engines(p.entry))

    ss = p.factory.successors(s)
    nose.tools.assert_true(ss.is_empty)

    p.engines.remove_engine(p.entry, simproc)
    nose.tools.assert_not_in(simproc, p.engines.list_engines(p.entry))

    ss = p.factory.successors(s)
    nose.tools.assert_true(ss.processed)

    # test stop points
    p.engines.insert_engine(0x400582, simproc)
    ss = p.factory.successors(s)
    nose.tools.assert_equal(ss[0].addr, 0x400582)

    p.engines.remove_engine(0x400582, simproc)

    ss = p.factory.successors(s)
    nose.tools.assert_true(ss.processed)

    # test amend
    p.engines.insert_engine(0x400580, p.engines.vex)
    ss = p.factory.successors(s)
    nose.tools.assert_equal(ss[0].addr, 0x400540)

    return


if __name__ == '__main__':
    test_engine_selector()
