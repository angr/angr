import os
import gc
import ana
import angr
import nose

def _bin(s):
    return os.path.join(os.path.dirname(__file__), '../../binaries', s)

def setup():
    ana.set_dl(ana.DictDataLayer())
def teardown():
    ana.set_dl(ana.SimpleDataLayer())

def pickle_callback(path):
    path.globals['pickled'] = True
def unpickle_callback(path):
    path.globals['unpickled'] = True
def priority_key(path):
    return hash(tuple(path.history.bbl_addrs)) # to help ensure determinism

@nose.with_setup(setup, teardown)
def test_basic():
    project = angr.Project(_bin('tests/cgc/sc2_0b32aa01_01'))
    path = project.factory.entry_state()
    spiller = angr.exploration_techniques.Spiller(pickle_callback=pickle_callback, unpickle_callback=unpickle_callback)
    spiller._pickle([path])

    del path
    gc.collect()
    path = spiller._unpickle(1)[0]

    assert path.globals['pickled']
    assert path.globals['unpickled']

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
    assert all(('pickled' not in path.globals and 'unpickled' not in path.globals) or (path.globals['pickled'] and path.globals['unpickled']) for path in pg.cut)

if __name__ == '__main__':
    test_basic()
    test_palindrome2()
