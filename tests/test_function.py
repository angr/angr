
import os

import nose.tools

import angr

test_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', '..', 'binaries', 'tests'))


def test_function_serialization():

    p = angr.Project(os.path.join(test_location, 'x86_64', 'fauxware'), auto_load_libs=False)
    cfg = p.analyses.CFG()

    func_main = cfg.kb.functions['main']
    s = func_main.serialize()

    nose.tools.assert_is(type(s), bytes)
    nose.tools.assert_greater(len(s), 10)

    f = angr.knowledge_plugins.Function.parse(s)
    nose.tools.assert_equal(func_main.addr, f.addr)
    nose.tools.assert_equal(func_main.name, f.name)


if __name__ == "__main__":
    test_function_serialization()
