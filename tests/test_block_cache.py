import angr

import logging
l = logging.getLogger("angr.tests")

import os
test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', '..', 'binaries', 'tests')

def test_block_cache():
    p = angr.Project(os.path.join(test_location, "x86_64", "fauxware"), translation_cache=True)
    b = p.factory.block(p.entry)
    assert p.factory.block(p.entry).vex is b.vex

    p = angr.Project(os.path.join(test_location, "x86_64", "fauxware"), translation_cache=False)
    b = p.factory.block(p.entry)
    assert p.factory.block(p.entry).vex is not b.vex

if __name__ == "__main__":
    test_block_cache()
