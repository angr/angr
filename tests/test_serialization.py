import cPickle as pickle
import nose
import angr
import ana
import os
import tempfile

internaltest_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../../binaries/tests'))
internaltest_files = [ 'argc_decide', 'argc_symbol', 'argv_test', 'counter', 'fauxware', 'fauxware.idb', 'manysum', 'pw', 'strlen', 'test_arrays', 'test_division', 'test_loops' ]
internaltest_arch = [ 'i386', 'armel' ]

def internaltest_vfg(p, cfg):
    state = tempfile.TemporaryFile()

    vfg = p.analyses.VFG(cfg=cfg)
    pickle.dump(vfg, state, -1)

    state.seek(0)
    vfg2 = pickle.load(state)
    nose.tools.assert_equals(vfg.final_states, vfg2.final_states)
    nose.tools.assert_equals(set(vfg.graph.nodes()), set(vfg2.graph.nodes()))

def internaltest_cfg(p):
    state = tempfile.TemporaryFile()

    cfg = p.analyses.CFGAccurate()
    pickle.dump(cfg, state, -1)

    state.seek(0)
    cfg2 = pickle.load(state)
    nose.tools.assert_equals(set(cfg.nodes()), set(cfg2.nodes()))
    nose.tools.assert_equals(cfg.unresolvables, cfg2.unresolvables)
    nose.tools.assert_set_equal(set(cfg.deadends), set(cfg2.deadends))

    return cfg

def internaltest_cfgfast(p):
    state = tempfile.TemporaryFile()

    cfg = p.analyses.CFGFast()

    # generate capstone blocks
    main_function = cfg.functions.function(name='main')
    for b in main_function.blocks:
        c = b.capstone  # pylint:disable=unused-variable

    pickle.dump(cfg, state, -1)

    state.seek(0)
    cfg2 = pickle.load(state)
    nose.tools.assert_equals(set(cfg.nodes()), set(cfg2.nodes()))

def internaltest_project(p):
    state = tempfile.TemporaryFile()
    pickle.dump(p, state, -1)

    state.seek(0)
    loaded_p = pickle.load(state)
    nose.tools.assert_equals(p.arch, loaded_p.arch)
    nose.tools.assert_equals(p.filename, loaded_p.filename)
    nose.tools.assert_equals(p.entry, loaded_p.entry)

def setup():
    tmp_dir = tempfile.mkdtemp(prefix='test_serialization_ana')
    ana.set_dl(ana.DirDataLayer(tmp_dir))
def teardown():
    ana.set_dl(ana.SimpleDataLayer())

@nose.with_setup(setup, teardown)
def test_serialization():
    for d in internaltest_arch:
        for f in internaltest_files:
            fpath = os.path.join(internaltest_location, d,f)
            if os.path.isfile(fpath) and os.access(fpath, os.X_OK):
                p = angr.Project(fpath)
                internaltest_project(p)

    p = angr.Project(os.path.join(internaltest_location, 'i386/fauxware'), load_options={'auto_load_libs': False})
    internaltest_cfgfast(p)

    cfg = internaltest_cfg(p)
    internaltest_vfg(p, cfg)

if __name__ == '__main__':
    test_serialization()
