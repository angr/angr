import functools

import nose
import angr
import networkx

import logging
l = logging.getLogger('angr.tests.test_kb_bbl')

import os
location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../../binaries/tests'))


def test_trim():
    p = angr.Project(location + "/cgc/stuff", auto_load_libs=False)
    cfg = p.analyses.CFGFast()

    basic_blocks = p.kb.basic_blocks
    for node in cfg.nodes():
        if node.size > 0:
            # ...we should be able to clean up the CFGNode here in order to save memory
            basic_blocks.add_block(node.addr, node.size, None)
            if node.addr == 0x80480dc:
                this_block = basic_blocks.get_block(0x80480d3)
                nose.tools.assert_equal(this_block.size, 9)


def test_handle():

    def _ovarlap_handler(this_item, other_item, node_addr=None):
        l.info('Handling %r vs %s @ %#x', this_item, other_item, node_addr)
        other_item.end = this_item.start
        l.info('Trimmed item: %r', this_item)
        return

    p = angr.Project(location + "/cgc/stuff", auto_load_libs=False)
    cfg = p.analyses.CFGFast()

    basic_blocks = p.kb.basic_blocks
    for node in cfg.nodes():
        if node.size > 0:
            # ...we should be able to clean up the CFGNode here in order to save memory
            basic_blocks.add_block(node.addr, node.size, None,
                                   overlap_mode='handle', overlap_handler=_ovarlap_handler,
                                   node_addr=node.addr)
            if node.addr == 0x80480dc:
                this_block = basic_blocks.get_block(0x80480d3)
                nose.tools.assert_equal(this_block.size, 9)


def test_raise():
    p = angr.Project(location + "/cgc/stuff", auto_load_libs=False)
    cfg = p.analyses.CFGFast()

    basic_blocks = p.kb.basic_blocks
    for node in cfg.nodes():
        if node.size > 0:
            # ...we should be able to clean up the CFGNode here in order to save memory
            if node.addr == 0x80480dc:
                nose.tools.assert_raises(angr.knowledge_plugins.basic_blocks.OverlappedBlocks,
                                         basic_blocks.add_block, node.addr, node.size,
                                         None, overlap_mode='raise')
                l.info("OverlappedBlocks has been caught!")
            else:
                basic_blocks.add_block(node.addr, node.size, None)


if __name__ == '__main__':
    test_trim()
    test_handle()
    test_raise()
