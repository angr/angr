import angr
from angr.exploration_techniques.spiller import Spiller
import os
import gc
import unittest
import claripy


def _bin(*s):
    return os.path.join(os.path.dirname(__file__), "..", "..", "binaries", *s)


def pickle_callback(state):
    state.globals["pickled"] = True


def unpickle_callback(sid, state):  # pylint:disable=unused-argument
    state.globals["unpickled"] = True


def priority_key(state):
    return state.addr * state.history.depth  # to help ensure determinism


class TestSpiller(unittest.TestCase):
    @classmethod
    def setUp(self):
        # clean up AST cache in claripy, because a cached AST might believe it
        # has been stored in ana after we clean up the ana storage

        claripy.ast.bv._bvv_cache.clear()
        claripy.ast.bv.BV._hash_cache.clear()

    def test_basic(self):
        project = angr.Project(_bin("tests", "cgc", "sc2_0b32aa01_01"), auto_load_libs=False)
        state = project.factory.entry_state()
        spiller = Spiller(pickle_callback=pickle_callback, unpickle_callback=unpickle_callback)
        spiller._pickle([state])

        del state
        gc.collect()
        state = spiller._unpickle(1)[0]

        assert state.globals["pickled"]
        assert state.globals["unpickled"]

    def test_palindrome2(self):
        project = angr.Project(_bin("tests", "cgc", "sc2_0b32aa01_01"), auto_load_libs=False)
        pg = project.factory.simulation_manager()
        limiter = angr.exploration_techniques.LengthLimiter(max_length=250)
        pg.use_technique(limiter)

        spiller = Spiller(
            pickle_callback=pickle_callback, unpickle_callback=unpickle_callback, priority_key=priority_key
        )
        pg.use_technique(spiller)
        # pg.step(until=lambda lpg: len(lpg.active) == 10)
        # pg.step(until=lambda lpg: len(lpg.spill_stage) > 15)
        # pg.step(until=lambda lpg: spiller._pickled_paths)
        pg.run()

        assert spiller._ever_pickled > 0
        assert spiller._ever_unpickled == spiller._ever_pickled
        assert all(
            ("pickled" not in state.globals and "unpickled" not in state.globals)
            or (state.globals["pickled"] and state.globals["unpickled"])
            for state in pg.cut
        )


if __name__ == "__main__":
    unittest.main()
