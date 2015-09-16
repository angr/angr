import cPickle as pickle
import nose
import angr
import ana
import os
import tempfile

internaltest_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../../binaries/tests'))

def internaltest_vfg(p, cfg):
    state = tempfile.TemporaryFile()

    vfg = p.analyses.VFG(cfg=cfg)
    pickle.dump(vfg, state)

    state.seek(0)
    vfg2 = pickle.load(state)
    nose.tools.assert_equals(vfg.final_states, vfg2.final_states)
    nose.tools.assert_equals(set(vfg.graph.nodes()), set(vfg2.graph.nodes()))

def internaltest_cfg(p):
    state = tempfile.TemporaryFile()

    cfg = p.analyses.CFG()
    pickle.dump(cfg, state)

    state.seek(0)
    cfg2 = pickle.load(state)
    nose.tools.assert_equals(set(cfg.nodes()), set(cfg2.nodes()))
    nose.tools.assert_equals(cfg.unresolvables, cfg2.unresolvables)
    nose.tools.assert_equals(cfg.deadends, cfg2.deadends)

    return cfg

def internaltest_project(p):
    state = tempfile.TemporaryFile()
    pickle.dump(p, state)

    state.seek(0)
    loaded_p = pickle.load(state)
    nose.tools.assert_equals(p.arch, loaded_p.arch)
    nose.tools.assert_equals(p.filename, loaded_p.filename)
    nose.tools.assert_equals(p.entry, loaded_p.entry)

def test_serialization():
    ana.set_dl(pickle_dir='/tmp/ana')

    internaltest_arch = [ 'i386', 'armel' ]
    for d in internaltest_arch:
        tests = os.path.join(internaltest_location, d)
        for f in os.listdir(tests):
            fpath = os.path.join(tests,f)
            if os.path.isfile(fpath) and os.access(fpath, os.X_OK):
                p = angr.Project(fpath)
                internaltest_project(p)

    p = angr.Project(os.path.join(internaltest_location, 'i386/fauxware'), load_options={'auto_load_libs': False})
    cfg = internaltest_cfg(p)
    internaltest_vfg(p, cfg)

if __name__ == '__main__':
    test_serialization()
