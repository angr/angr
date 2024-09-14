from __future__ import annotations
import pickle
import angr
import nose


def test_pickle_state():
    b = angr.Project("/home/angr/angr/angr/tests/blob/x86_64/fauxware")
    p = b.path_generator.entry_point()
    p.state.inspect.make_breakpoint("mem_write")
    nose.tools.assert_true("inspector" in p.state.plugins)

    s_str = pickle.dumps(p.state)
    s2 = pickle.loads(s_str)

    nose.tools.assert_is(p.state, s2)
    del p
    del s2

    import gc

    gc.collect()

    s2 = pickle.loads(s_str)
    nose.tools.assert_true("inspector" not in s2.plugins)


if __name__ == "__main__":
    test_pickle_state()
