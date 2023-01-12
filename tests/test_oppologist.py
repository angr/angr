import os

import angr

test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..")


def _ultra_oppologist(p, s):
    old_ops = dict(angr.engines.vex.claripy.irop.operations)
    try:
        angr.engines.vex.claripy.irop.operations.clear()
        angr.engines.vex.claripy.irop.operations["Iop_Add32"] = old_ops["Iop_Add32"]

        pg = p.factory.simulation_manager(s)
        pg.use_technique(angr.exploration_techniques.Oppologist())
        pg.explore()

        return pg
    finally:
        angr.engines.vex.claripy.irop.operations.update(old_ops)


def test_fauxware_oppologist():
    p = angr.Project(os.path.join(test_location, "binaries", "tests", "i386", "fauxware"))
    s = p.factory.full_init_state(remove_options={angr.options.LAZY_SOLVES, angr.options.EXTENDED_IROP_SUPPORT})

    pg = _ultra_oppologist(p, s)
    assert len(pg.deadended) == 1
    assert len(pg.deadended[0].posix.dumps(0)) == 18
    stdout = pg.deadended[0].posix.dumps(1)
    if b"trusted user" in stdout:
        assert stdout.count(b"\n") == 3
    else:
        assert stdout.count(b"\n") == 2


def test_cromu_70():
    p = angr.Project(os.path.join(test_location, "binaries", "tests", "cgc", "CROMU_00070"))
    inp = bytes.fromhex(
        "030e000001000001001200010000586d616ce000000600030000040dd0000000000600000606000006030e000001000001003200010000586d616ce0030000000000030e000001000001003200010000586d616ce003000000000006000006030e000001000001003200010000586d616ce0030000df020000"
    )
    s = p.factory.full_init_state(
        add_options={angr.options.UNICORN},
        remove_options={angr.options.LAZY_SOLVES, angr.options.SUPPORT_FLOATING_POINT},
        stdin=inp,
    )

    # import traceit
    pg = p.factory.simulation_manager(s)
    pg.use_technique(angr.exploration_techniques.Oppologist())
    pg.run(n=50)
    assert pg.one_active.history.block_count > 1500


def run_all():
    functions = globals()
    all_functions = dict(filter((lambda kv: kv[0].startswith("test_")), functions.items()))
    for f in sorted(all_functions.keys()):
        if hasattr(all_functions[f], "__call__"):
            print(f)
            all_functions[f]()


if __name__ == "__main__":
    run_all()
