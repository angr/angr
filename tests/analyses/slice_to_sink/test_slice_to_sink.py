import nose
import os

from angr.analyses.slice_to_sink import SliceToSink
from angr.project import Project


BINARIES_PATH = os.path.join(
    os.path.dirname(os.path.realpath(__file__)),
    '..', '..', '..', '..', 'binaries-private', 'operation-mango'
)
BINARY_PATH = os.path.join(BINARIES_PATH, 'air-live-bu-2015', 'cgi_test.cgi')
PROJECT = Project(BINARY_PATH, auto_load_libs=False)
CFG = PROJECT.analyses.CFGFast()
PRINTF = CFG.kb.functions.function(name='printf', plt=False)
PRINTF_NODE = CFG.model.get_all_nodes(PRINTF.addr)[0]


def test_get_transitions_from_slice():
    transitions = {1: [2, 3]}
    my_slice = SliceToSink(None, transitions)

    nose.tools.assert_dict_equal(my_slice.transitions, transitions)


def test_get_entrypoints_from_slice():
    transitions = {0: [2], 1: [2, 3], 2: [4, 5]}
    my_slice = SliceToSink(None, transitions)

    nose.tools.assert_list_equal(my_slice.entrypoints, [0, 1])


def test_add_transitions_to_a_node_updates_the_slice():
    printf_predecessor = PRINTF_NODE.predecessors[0]

    my_slice = SliceToSink(None, {1: [2, 3]})

    expected_result = {
        1: [2, 3],
        printf_predecessor.addr: [PRINTF.addr],
    }
    my_slice.add_transitions_to(PRINTF_NODE)
    result = my_slice._transitions

    nose.tools.assert_dict_equal(result, expected_result)


def test_nodes():
    my_slice = SliceToSink(None, {
        1: [2, 3],
        2: [3],
    })

    expected_result = [1, 2, 3]
    result = my_slice.nodes

    nose.tools.assert_list_equal(result, expected_result)


def test_transitions_as_tuples():
    my_slice = SliceToSink(None, {
        1: [2, 3],
        2: [3]
    })

    expected_result = [(1, 2), (1, 3), (2, 3)]
    result = my_slice.transitions_as_tuples

    nose.tools.assert_list_equal(result, expected_result)


def test_emptyness():
    printf_predecessor = PRINTF_NODE.predecessors[0]

    empty_slice = SliceToSink(PRINTF, {})
    non_empty_slice = SliceToSink(PRINTF, { printf_predecessor.addr: [PRINTF.addr] })

    nose.tools.assert_equals(empty_slice.is_empty(), True)
    nose.tools.assert_equals(non_empty_slice.is_empty(), False)
