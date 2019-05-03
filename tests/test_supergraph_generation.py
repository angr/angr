
import logging
import os
import nose

from common import bin_location
import angr

test_location = os.path.join(bin_location, 'tests')

def test_supergraph_generation():
    p = angr.Project(test_location + '/x86_64/fauxware', auto_load_libs=False)
    p.analyses.CFGFast()
    main = p.kb.functions['main']
    supergraph_generator = p.analyses.SupergraphGeneration(main)
    breakpoint()

if __name__ == '__main__':
    logging.getLogger('angr.analyses.supergraph_generation').setLevel(logging.INFO)
    test_supergraph_generation()
