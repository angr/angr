import nose
import angr

import logging
l = logging.getLogger('angr.tests.test_views_transitions')

import os
location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../../binaries/tests'))


def test_transitions_view():
    p = angr.Project(location + "/armel/fauxware", auto_load_libs=False)

    p.kb.register_plugin('blocks', angr.knowledge_plugins.BasicBlocksPlugin())

    blocks = angr.BlocksView(p.kb)
    trans = angr.TransitionsView(p.kb, blocks=blocks)

    p.kb.blocks.mark_block(0x8411, 10)
    nose.tools.assert_true(trans.has_transition(0x8411, 0x84e5, 'call'))


if __name__ == '__main__':
    test_transitions_view()
