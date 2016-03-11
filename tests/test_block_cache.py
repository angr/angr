import angr

import logging
l = logging.getLogger("angr.tests")

import os
test_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../../binaries/tests'))

def test_block_cache():
    p = angr.Project(os.path.join(test_location, "x86_64", "fauxware"), translation_cache=True)
    b = p.factory.block(p.entry)
    assert p.factory.block(p.entry) is b

    p = angr.Project(os.path.join(test_location, "x86_64", "fauxware"), translation_cache=False)
    b = p.factory.block(p.entry)
    assert p.factory.block(p.entry) is not b

if __name__ == "__main__":
    test_block_cache()
