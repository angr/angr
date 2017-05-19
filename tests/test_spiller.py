import os
import gc
import ana
import angr

def _bin(s):
    return os.path.join(os.path.dirname(__file__), '../../binaries', s)

def test_basic():
    ana.set_dl(ana.DictDataLayer())

    def pickle_callback(path): path.info['pickled'] = True
    def unpickle_callback(path): path.info['unpickled'] = True

    project = angr.Project(_bin('tests/cgc/sc2_0b32aa01_01'))
    path = project.factory.path()
    spiller = angr.exploration_techniques.Spiller(pickle_callback=pickle_callback, unpickle_callback=unpickle_callback)
    spiller._pickle([path])
    del path
    gc.collect()
    path = spiller._unpickle(1)[0]
    assert path.info['pickled']
    assert path.info['unpickled']

def test_palindrome2():
    ana.set_dl(ana.DictDataLayer())

    project = angr.Project(_bin('tests/cgc/sc2_0b32aa01_01'))
    pg = project.factory.path_group()
    pg.active[0].state.options.discard('LAZY_SOLVES')
    limiter = angr.exploration_techniques.LengthLimiter(max_length=250)
    pg.add_technique(limiter)

    def pickle_callback(path): path.info['pickled'] = True
    def unpickle_callback(path): path.info['unpickled'] = True
    def priority_key(path): return hash(tuple(path.addr_trace)) # to help ensure determinism
    spiller = angr.exploration_techniques.Spiller(
        pickle_callback=pickle_callback, unpickle_callback=unpickle_callback,
        priority_key=priority_key
    )
    pg.add_technique(spiller)
    #pg.step(until=lambda lpg: len(lpg.active) == 10)
    #pg.step(until=lambda lpg: len(lpg.spill_stage) > 15)
    #pg.step(until=lambda lpg: spiller._pickled_paths)
    pg.run()
    assert spiller._ever_pickled > 0
    assert spiller._ever_unpickled == spiller._ever_pickled
    assert all(('pickled' not in path.info and 'unpickled' not in path.info) or (path.info['pickled'] and path.info['unpickled']) for path in pg.cut)
