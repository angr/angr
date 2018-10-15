import os
import sys

import angr
import nose.tools

test_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', '..', 'binaries', 'tests'))


def test_various_loops():
    p = angr.Project(os.path.join(test_location, 'x86_64', 'various_loops'), auto_load_libs=False)

    cfg = p.analyses.CFGFast(normalize=True)

    state = p.factory.entry_state()
    state.register_plugin('loop_data', angr.state_plugins.SimStateLoopData())

    dummy = p.loader.main_object.get_symbol('dummy')
    bvs = state.solver.BVS(dummy.name, 8 * dummy.size)
    state.memory.store(dummy.rebased_addr, bvs, endness='Iend_LE')

    simgr = p.factory.simulation_manager(state)

    simgr.use_technique(angr.exploration_techniques.LoopSeer(cfg=cfg, functions=None, bound=None))

    simgr.run()

    nose.tools.assert_equal(len(simgr.deadended), 10)
    nose.tools.assert_equal(len(simgr.deadended[0].loop_data.back_edge_trip_counts), 14)

    for i, d in enumerate(simgr.deadended):
        f = p.kb.functions.function(name='symbolic_loop')
        l = p.analyses.LoopFinder(functions=[f]).loops[0]
        nose.tools.assert_equal(d.loop_data.back_edge_trip_counts[l.entry.addr][0], i)

        f = p.kb.functions.function(name='for_loop')
        l = p.analyses.LoopFinder(functions=[f]).loops[0]
        nose.tools.assert_equal(d.loop_data.back_edge_trip_counts[l.entry.addr][0], 9)

        f = p.kb.functions.function(name='while_loop')
        l = p.analyses.LoopFinder(functions=[f]).loops[0]
        nose.tools.assert_equal(d.loop_data.back_edge_trip_counts[l.entry.addr][0], 9)

        f = p.kb.functions.function(name='do_while_loop')
        l = p.analyses.LoopFinder(functions=[f]).loops[0]
        nose.tools.assert_equal(d.loop_data.header_trip_counts[l.entry.addr][0], 9)

        f = p.kb.functions.function(name='nullify')
        l = p.analyses.LoopFinder(functions=[f]).loops[0]
        nose.tools.assert_equal(len(d.loop_data.back_edge_trip_counts[l.entry.addr]), 8)
        nose.tools.assert_equal(d.loop_data.back_edge_trip_counts[l.entry.addr][0], 9)

        f = p.kb.functions.function(name='nested_for_loop')
        ol = p.analyses.LoopFinder(functions=[f]).loops[0]
        il = ol.subloops[0]
        nose.tools.assert_equal(d.loop_data.back_edge_trip_counts[ol.entry.addr][0], 3)
        nose.tools.assert_equal(len(d.loop_data.back_edge_trip_counts[il.entry.addr]), 3)
        nose.tools.assert_true(all(s == 3 for s in d.loop_data.back_edge_trip_counts[il.entry.addr]))

        f = p.kb.functions.function(name='nested_while_loop')
        ol = p.analyses.LoopFinder(functions=[f]).loops[0]
        il = ol.subloops[0]
        nose.tools.assert_equal(d.loop_data.back_edge_trip_counts[ol.entry.addr][0], 3)
        nose.tools.assert_equal(len(d.loop_data.back_edge_trip_counts[il.entry.addr]), 3)
        nose.tools.assert_true(all(s == 3 for s in d.loop_data.back_edge_trip_counts[il.entry.addr]))

        f = p.kb.functions.function(name='nested_do_while_loop')
        ol = p.analyses.LoopFinder(functions=[f]).loops[0]
        il = ol.subloops[0]
        nose.tools.assert_equal(d.loop_data.header_trip_counts[ol.entry.addr][0], 3)
        nose.tools.assert_equal(len(d.loop_data.header_trip_counts[il.entry.addr]), 3)
        nose.tools.assert_true(all(s == 3 for s in d.loop_data.header_trip_counts[il.entry.addr]))

        f = p.kb.functions.function(name='break_for_loop')
        l = p.analyses.LoopFinder(functions=[f]).loops[0]
        nose.tools.assert_equal(d.loop_data.back_edge_trip_counts[l.entry.addr][0], 9)

        f = p.kb.functions.function(name='break_do_while_loop')
        l = p.analyses.LoopFinder(functions=[f]).loops[0]
        nose.tools.assert_equal(d.loop_data.header_trip_counts[l.entry.addr][0], 9)


def test_loops_with_invalid_parameter():
    p = angr.Project(os.path.join(test_location, 'x86_64', 'test_loops'), auto_load_libs=False)

    state = p.factory.entry_state()
    state.register_plugin('loop_data', angr.state_plugins.SimStateLoopData())
    simgr = p.factory.simulation_manager(state)

    simgr.use_technique(angr.exploration_techniques.LoopSeer(functions=['main', 0x1234], bound=None))

    simgr.run()

    nose.tools.assert_equal(len(simgr.deadended[0].loop_data.back_edge_trip_counts), 3)
    nose.tools.assert_equal(simgr.deadended[0].loop_data.back_edge_trip_counts[0x400665][0], 10)
    nose.tools.assert_equal(len(simgr.deadended[0].loop_data.back_edge_trip_counts[0x400665]), 10)
    nose.tools.assert_equal(simgr.deadended[0].loop_data.back_edge_trip_counts[0x400675][0], 10)
    nose.tools.assert_equal(simgr.deadended[0].loop_data.back_edge_trip_counts[0x4006b2][0], 100)


def test_arrays():
    p = angr.Project(os.path.join(test_location, 'x86_64', 'test_arrays'), auto_load_libs=False)

    cfg = p.analyses.CFGFast(normalize=True)

    state = p.factory.entry_state()
    state.register_plugin('loop_data', angr.state_plugins.SimStateLoopData())
    simgr = p.factory.simulation_manager(state)

    simgr.use_technique(angr.exploration_techniques.LoopSeer(cfg=cfg, functions='main', bound=None))

    simgr.run()

    nose.tools.assert_equal(len(simgr.deadended[0].loop_data.back_edge_trip_counts), 2)
    nose.tools.assert_equal(simgr.deadended[0].loop_data.back_edge_trip_counts[0x400636][0], 26)
    nose.tools.assert_equal(simgr.deadended[0].loop_data.back_edge_trip_counts[0x4005fd][0], 26)


def test_loop_limiter():
    p = angr.Project(os.path.join(test_location, 'x86_64', 'test_arrays'), auto_load_libs=False)

    cfg = p.analyses.CFGFast(normalize=True)

    state = p.factory.entry_state()
    state.register_plugin('loop_data', angr.state_plugins.SimStateLoopData())
    simgr = p.factory.simulation_manager(state)

    simgr.use_technique(angr.exploration_techniques.LoopSeer(cfg=cfg, functions='main', bound=5))

    simgr.run()

    nose.tools.assert_true('spinning' in simgr.stashes)
    nose.tools.assert_equal(simgr.spinning[0].loop_data.back_edge_trip_counts[0x4005fd][0], 6)


if __name__ == "__main__":
    if len(sys.argv) > 1:
        globals()['test_' + sys.argv[1]]()

    else:
        g = globals().copy()

        for k, v in g.items():
            if k.startswith("test_") and hasattr(v, '__call__'):
                print(k)
                v()
