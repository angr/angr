import functools

import nose
import angr
import networkx

import logging

l = logging.getLogger('angr.tests.test_kb_bbl')

import os

location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../../binaries/tests'))


def test_reconstruct():
    p = angr.Project(location + "/i386/fauxware", auto_load_libs=False)
    cfg = p.analyses.CFGFast()

    basic_blocks = p.kb.basic_blocks
    indirect_jumps = p.kb.indirect_jumps

    for node in cfg.nodes():
        if node.size > 0:
            basic_blocks.add_block(node.addr, node.size, node.thumb)

    transitions = p.kb.transitions

    for src_node, dst_node, attrs in cfg.graph.edges_iter(data=True):
        if src_node.is_simprocedure or dst_node.is_simprocedure or \
                attrs['jumpkind'] in ('Ijk_Ret', 'Ijk_FakeRet'):
            indirect_jumps.register_jump(src_node.addr, dst_node.addr,
                                         attrs['jumpkind'], attrs['ins_addr'], attrs['stmt_idx'])

    absent_transitions = []
    for src_node, dst_node, attrs in cfg.graph.edges_iter(data=True):
        if not transitions.has_transition(src_node.addr, dst_node.addr):
            l.info("%s -> %s", src_node, dst_node)
            absent_transitions.append((src_node, dst_node, attrs))

    nose.tools.assert_less_equal(len(absent_transitions), 3, str(absent_transitions))
    return


def test_observer():
    pass


if __name__ == '__main__':
    test_reconstruct()
    test_observer()
