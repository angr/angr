import angr
import nose.tools
import os
import sys

test_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', '..', 'binaries', 'tests'))

def test_various_loops():
    p = angr.Project(os.path.join(test_location, 'x86_64', 'various_loops'))

    cfg = p.analyses.CFGAccurate(normalize=True)

    state = p.factory.entry_state()
    state.register_plugin('loop_data', angr.state_plugins.SimStateLoopData())
    simgr = p.factory.simgr(state)

    simgr.use_technique(angr.exploration_techniques.LoopSeer(cfg=cfg, functions=None, bound=None))

    simgr.run()

    nose.tools.assert_equals(len(simgr.deadended[0].loop_data.trip_counts), 13)

    # for_loop
    nose.tools.assert_equals(simgr.deadended[0].loop_data.trip_counts[0x400529][0], 9)

    # while_loop
    nose.tools.assert_equals(simgr.deadended[0].loop_data.trip_counts[0x400557][0], 9)

    # do_while_loop
    nose.tools.assert_equals(simgr.deadended[0].loop_data.trip_counts[0x400572][0], 9)

    # nullify
    nose.tools.assert_equals(len(simgr.deadended[0].loop_data.trip_counts[0x4004f7]), 7)

    # nested_for_loop
    nose.tools.assert_equals(simgr.deadended[0].loop_data.trip_counts[0x4005df][0], 3)
    nose.tools.assert_equals(len(simgr.deadended[0].loop_data.trip_counts[0x4005d5]), 3)
    nose.tools.assert_true(all(s == 3 for s in simgr.deadended[0].loop_data.trip_counts[0x4005d5]))

    # nested_while_loop
    nose.tools.assert_equals(simgr.deadended[0].loop_data.trip_counts[0x400630][0], 3)
    nose.tools.assert_equals(len(simgr.deadended[0].loop_data.trip_counts[0x400626]), 3)
    nose.tools.assert_true(all(s == 3 for s in simgr.deadended[0].loop_data.trip_counts[0x400626]))

    # nested_do_while_loop
    nose.tools.assert_equals(simgr.deadended[0].loop_data.trip_counts[0x400644][0], 3)
    nose.tools.assert_equals(len(simgr.deadended[0].loop_data.trip_counts[0x40064b]), 3)
    nose.tools.assert_true(all(s == 3 for s in simgr.deadended[0].loop_data.trip_counts[0x40064b]))

    # break_for_loop
    nose.tools.assert_equals(simgr.deadended[0].loop_data.trip_counts[0x4006bd][0], 9)

    # break_do_while_loop
    nose.tools.assert_equals(simgr.deadended[0].loop_data.trip_counts[0x4006d1][0], 9)

def test_loops():
    p = angr.Project(os.path.join(test_location, 'x86_64', 'test_loops'))

    cfg = p.analyses.CFGAccurate(normalize=True)

    state = p.factory.entry_state()
    state.register_plugin('loop_data', angr.state_plugins.SimStateLoopData())
    simgr = p.factory.simgr(state)

    simgr.use_technique(angr.exploration_techniques.LoopSeer(cfg=cfg, functions='main', bound=None))

    simgr.run()

    nose.tools.assert_equals(len(simgr.deadended[0].loop_data.trip_counts), 3)
    nose.tools.assert_equals(simgr.deadended[0].loop_data.trip_counts[0x400665][0], 10)
    nose.tools.assert_equals(len(simgr.deadended[0].loop_data.trip_counts[0x400665]), 10)
    nose.tools.assert_equals(simgr.deadended[0].loop_data.trip_counts[0x400675][0], 10)
    nose.tools.assert_equals(simgr.deadended[0].loop_data.trip_counts[0x4006b2][0], 100)

def test_arrays():
    p = angr.Project(os.path.join(test_location, 'x86_64', 'test_arrays'))

    cfg = p.analyses.CFGAccurate(normalize=True)

    state = p.factory.entry_state()
    state.register_plugin('loop_data', angr.state_plugins.SimStateLoopData())
    simgr = p.factory.simgr(state)

    simgr.use_technique(angr.exploration_techniques.LoopSeer(cfg=cfg, functions='main', bound=None))

    simgr.run()

    nose.tools.assert_equals(len(simgr.deadended[0].loop_data.trip_counts), 2)
    nose.tools.assert_equals(simgr.deadended[0].loop_data.trip_counts[0x400636][0], 26)
    nose.tools.assert_equals(simgr.deadended[0].loop_data.trip_counts[0x4005fd][0], 26)

if __name__ == "__main__":
    if len(sys.argv) > 1:
        globals()['test_' + sys.argv[1]]()

    else:
        g = globals().copy()

        for k, v in g.iteritems():
            if k.startswith("test_") and hasattr(v, '__call__'):
                v()
