import functools
import itertools

import nose
import angr
import networkx

import logging
l = logging.getLogger('angr.tests.test_kb_transitions')

import os
location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../../binaries/tests'))


def test_transitions():
    transitions = angr.knowledge_plugins.transitions.TransitionsPlugin()

    base_graph = networkx.complete_graph(16)
    jumpkinds = itertools.cycle(('Ijk_Boring', 'Ijk_Call', 'Ijk_SysCall', 'Ijk_Ret', 'Ijk_FakeRet'))
    dummy_cnt = itertools.count(0)
    for u, v in base_graph.edges_iter():
        jumpkind = next(jumpkinds)
        transitions.add_transition(u, v, jumpkind, ins_addr=next(dummy_cnt), stmt_idx=next(dummy_cnt))

    nose.tools.assert_true(transitions.has_transition(0))
    nose.tools.assert_true(transitions.has_transition(0, 1))
    nose.tools.assert_true(transitions.has_transition(0, 1, 'transition'))
    nose.tools.assert_true(transitions.has_transition(0, 1, 'transition', ins_addr=0))
    nose.tools.assert_false(transitions.has_transition(0, 1024))
    nose.tools.assert_false(transitions.has_transition(0, 1, 'transition', ins_addr=1))
    nose.tools.assert_false(transitions.has_transition(0, 1, 'fakeret'))

    trans = transitions.get_transition(0, 1, 'transition')
    nose.tools.assert_equal(trans.from_addr, 0)
    nose.tools.assert_equal(trans.to_addr, 1)
    nose.tools.assert_equal(trans.type, 'transition')
    nose.tools.assert_equal(trans.attrs['ins_addr'], 0)
    nose.tools.assert_equal(trans.attrs['stmt_idx'], 1)

    nose.tools.assert_equal(len(list(transitions.iter_transitions(0))), 15)
    nose.tools.assert_equal(len(list(transitions.iter_transitions(0, 10))), 1)
    nose.tools.assert_equal(len(list(transitions.iter_transitions(0, 16))), 0)
    nose.tools.assert_equal(len(list(transitions.iter_transitions(0, type='call'))), 6)
    nose.tools.assert_equal(len(list(transitions.iter_transitions(0, ins_addr=32))), 0)
    nose.tools.assert_equal(len(list(transitions.iter_transitions(0, ins_addr=20))), 1)

    nose.tools.assert_equal(transitions.count_transitions(0), 15)
    nose.tools.assert_equal(transitions.count_transitions(to_addr=1), 1)
    nose.tools.assert_equal(transitions.count_transitions(to_addr=2), 2)
    nose.tools.assert_equal(transitions.count_transitions(type='call'), 48)
    nose.tools.assert_equal(transitions.count_transitions(ins_addr=0), 1)
    nose.tools.assert_equal(transitions.count_transitions(), 120)


if __name__ == '__main__':
    with dbg.traced():
        test_transitions()
