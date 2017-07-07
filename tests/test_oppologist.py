import os

import angr

test_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../..'))

def _ultra_oppologist(p, s):
    old_ops = dict(angr.engines.vex.irop.operations)
    try:
        angr.engines.vex.irop.operations.clear()
        angr.engines.vex.irop.operations['Iop_Add32'] = old_ops['Iop_Add32']

        pg = p.factory.simgr(s)
        pg.use_technique(angr.exploration_techniques.Oppologist())
        pg.explore()

        return pg
    finally:
        angr.engines.vex.irop.operations.update(old_ops)

def test_fauxware_oppologist():
    p = angr.Project(os.path.join(test_location, 'binaries/tests/i386/fauxware'))
    s = p.factory.full_init_state(
        remove_options={ angr.options.LAZY_SOLVES }
    )

    pg = _ultra_oppologist(p, s)
    assert len(pg.deadended) == 1
    assert len(pg.deadended[0].posix.dumps(0)) == 18
    assert pg.deadended[0].posix.dumps(1).count("\n") == 3

def test_cromu_70():
    p = angr.Project(os.path.join(test_location, 'binaries/tests/cgc/CROMU_00070'))
    s = p.factory.full_init_state(
        add_options={ angr.options.UNICORN },
        remove_options={ angr.options.LAZY_SOLVES, angr.options.SUPPORT_FLOATING_POINT }
    )

    inp = "030e000001000001001200010000586d616ce000000600030000040dd0000000000600000606000006030e000001000001003200010000586d616ce0030000000000030e000001000001003200010000586d616ce003000000000006000006030e000001000001003200010000586d616ce0030000df020000".decode('hex')
    s.posix.files[0].content.store(0, inp)
    s.posix.files[0].size = len(inp)

    #import traceit
    pg = p.factory.simgr(s)
    pg.use_technique(angr.exploration_techniques.Oppologist())
    pg.explore()
    assert pg.one_deadended.history.block_count > 1500


if __name__ == '__main__':
    import sys
    globals()['test_' + sys.argv[1]]()
