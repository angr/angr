import os
import logging
import networkx
import nose.tools
import angr

l = logging.getLogger('angr_tests.dataflowgraph')

test_location = str(os.path.dirname(os.path.realpath(__file__)))

def test_inout():
    p = angr.Project(os.path.join(test_location, "build/x86_64/track_user_input"))
    a=p.analyses.VSA_DDG(start_addr=p.ld.main_bin.get_symbol("main").addr, interfunction_level=2, keep_addrs=True)
    b=p.analyses.DataFlowGraph(a)

    # scanf writes user input to some variable, stuff happens, and printf
    # outputs content that is data-dependent to it.
    # The dataflow graph *must* contain a path between those two.
    condition = networkx.has_path(b.graph, (0x3000030, -1), (0x3000040, -1))
    nose.tools.assert_true(condition)

if __name__ == "__main__":
    test_inout()
