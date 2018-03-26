import os
import gc
import ana
import angr
import nose

def _bin(s):
    return os.path.join(os.path.dirname(__file__), '../../binaries', s)

def setup():

    # clean up AST cache in claripy, because a cached AST might believe it has been stored in ana after we clean up the
    # ana storage
    import claripy
    claripy.ast.bv._bvv_cache.clear()
    claripy.ast.bv.BV._hash_cache.clear()

    ana.set_dl(ana.DictDataLayer())
def teardown():
    ana.set_dl(ana.SimpleDataLayer())

def pickle_callback(state):
    state.globals['pickled'] = True
def unpickle_callback(state):
    state.globals['unpickled'] = True
def priority_key(state):
    return state.addr * state.history.depth # to help ensure determinism

@nose.with_setup(setup, teardown)
def test_basic():
    project = angr.Project(_bin('tests/cgc/sc2_0b32aa01_01'))
    state = project.factory.entry_state()
    spiller = angr.exploration_techniques.Spiller(pickle_callback=pickle_callback, unpickle_callback=unpickle_callback)
    spiller._pickle([state])

    del state
    gc.collect()
    state = spiller._unpickle(1)[0]

    assert state.globals['pickled']
    assert state.globals['unpickled']

@nose.with_setup(setup, teardown)
def test_palindrome2():
    project = angr.Project(_bin('tests/cgc/sc2_0b32aa01_01'))
    pg = project.factory.simgr()
    limiter = angr.exploration_techniques.LengthLimiter(max_length=250)
    pg.use_technique(limiter)

    spiller = angr.exploration_techniques.Spiller(
        pickle_callback=pickle_callback, unpickle_callback=unpickle_callback,
        priority_key=priority_key
    )
    pg.use_technique(spiller)
    #pg.step(until=lambda lpg: len(lpg.active) == 10)
    #pg.step(until=lambda lpg: len(lpg.spill_stage) > 15)
    #pg.step(until=lambda lpg: spiller._pickled_paths)
    pg.run()

    assert spiller._ever_pickled > 0
    assert spiller._ever_unpickled == spiller._ever_pickled
    assert all(
        ('pickled' not in state.globals and 'unpickled' not in state.globals) or
        (state.globals['pickled'] and state.globals['unpickled'])
        for state in pg.cut
    )

if __name__ == '__main__':
    setup()
    test_basic()
    test_palindrome2()
    teardown()
