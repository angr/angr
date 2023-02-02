import tempfile
import pickle
import shutil
import angr
import os

internaltest_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "binaries", "tests")
internaltest_files = [
    "argc_decide",
    "argc_symbol",
    "argv_test",
    "counter",
    "fauxware",
    "fauxware.idb",
    "manysum",
    "pw",
    "strlen",
    "test_arrays",
    "test_division",
    "test_loops",
]
internaltest_arch = ["i386", "armel"]


def internaltest_vfg(p, cfg):
    vfg = p.analyses.VFG(cfg=cfg)
    v = angr.vaults.VaultDict()
    state = v.dumps(vfg)
    vfg2 = v.loads(state)
    assert vfg.final_states == vfg2.final_states
    assert set(vfg.graph.nodes()) == set(vfg2.graph.nodes())


def internaltest_cfg(p):
    state = tempfile.TemporaryFile()

    cfg = p.analyses.CFGEmulated()
    pickle.dump(cfg, state, -1)

    state.seek(0)
    cfg2 = pickle.load(state)
    assert set(cfg.model.nodes()) == set(cfg2.model.nodes())
    assert cfg.unresolvables == cfg2.unresolvables
    assert set(cfg.deadends) == set(cfg2.deadends)

    return cfg


def internaltest_cfgfast(p):
    state = tempfile.TemporaryFile()

    cfg = p.analyses.CFGFast()

    # generate capstone blocks
    main_function = cfg.functions.function(name="main")
    for b in main_function.blocks:
        b.capstone

    pickle.dump(cfg, state, -1)

    state.seek(0)
    cfg2 = pickle.load(state)
    assert set(cfg.model.nodes()) == set(cfg2.model.nodes())


def internaltest_project(fpath):
    tpath = tempfile.mktemp()
    shutil.copy(fpath, tpath)

    p = angr.Project(tpath, auto_load_libs=False)
    state = pickle.dumps(p, -1)
    loaded_p = pickle.loads(state)
    assert p is not loaded_p
    assert p.arch == loaded_p.arch
    assert p.filename == loaded_p.filename
    assert p.entry == loaded_p.entry

    simgr = loaded_p.factory.simulation_manager()
    simgr.run(n=10)
    assert len(simgr.errored) == 0


def test_analyses():
    p = angr.Project(os.path.join(internaltest_location, "i386", "fauxware"), load_options={"auto_load_libs": False})
    cfg = p.analyses.CFG()
    cfb = p.analyses.CFB(kb=cfg.kb)
    vrf = p.analyses.VariableRecoveryFast(p.kb.functions["main"])

    assert len(p.kb.functions) > 0
    assert len(pickle.loads(pickle.dumps(p.kb, -1)).functions) > 0

    state = pickle.dumps((p, cfg, cfb, vrf), -1)
    del p
    del cfg
    del cfb
    del vrf
    import gc

    gc.collect()

    p, cfg, cfb, vrf = pickle.loads(state)
    assert p.kb is not None
    assert p.kb.functions is not None
    assert cfg.kb is not None
    assert len(p.kb.functions) > 0


def test_serialization():
    for d in internaltest_arch:
        for f in internaltest_files:
            fpath = os.path.join(internaltest_location, d, f)
            if os.path.isfile(fpath) and os.access(fpath, os.X_OK):
                internaltest_project(fpath)

    p = angr.Project(os.path.join(internaltest_location, "i386", "fauxware"), load_options={"auto_load_libs": False})
    internaltest_cfgfast(p)

    cfg = internaltest_cfg(p)
    internaltest_vfg(p, cfg)


if __name__ == "__main__":
    test_analyses()
    test_serialization()
