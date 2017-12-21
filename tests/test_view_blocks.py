import nose
import angr

import logging
l = logging.getLogger('angr.tests.test_views_transitions')

import os
location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../../binaries/tests'))


def test_blocks_view():
    p = angr.Project(location + "/armel/fauxware", auto_load_libs=False)

    p.kb.register_plugin('blocks', angr.knowledge_plugins.BasicBlocksPlugin())
    p.kb.blocks.mark_block(0x8411, 6)

    blocks = angr.BlocksView(p.kb)
    block = blocks.get_block(0x8411)

    nose.tools.assert_is_not_none(block)
    nose.tools.assert_equal(block.size, 6)
    nose.tools.assert_equal(block.bytes, b"\x08\xb5\x00\xf0\x67\xf8")


if __name__ == '__main__':
    test_blocks_view()
