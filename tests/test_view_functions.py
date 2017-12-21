import nose
import angr

import logging
l = logging.getLogger('angr.tests.test_views_transitions')

import os
location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../../binaries/tests'))


def test_functions_view():
    p = angr.Project(location + "/armel/fauxware", auto_load_libs=False)

    p.kb.register_plugin('blocks', angr.knowledge_plugins.BasicBlocksPlugin())
    p.kb.register_plugin('funcs', angr.knowledge_plugins.FunctionsPlugin())

    p.kb.blocks.mark_block(0x84e5, 14)
    p.kb.blocks.mark_block(0x84f3, 2)
    p.kb.funcs.register_function(0x84e5)
    p.kb.funcs.register_function(0x8479)

    funcs = angr.FunctionsView(p.kb)
    func = funcs.get_function(0x84e5)

    nose.tools.assert_is_not_none(func)

    nose.tools.assert_equal(len(func.in_transitions), 0)
    nose.tools.assert_equal(len(func.out_transitions), 1)

    out_edge = (0x84e5, 0x8479, 'transition', {'jumpkind': 'Ijk_Boring', 'ins_addr': 0x84efL, 'stmt_idx': 'default'})
    nose.tools.assert_equal(func.out_transitions[0].to_nx_edge(), out_edge)

    nose.tools.assert_equal(len(func.call_sites), 0)
    nose.tools.assert_equal(len(func.callout_sites), 0)
    nose.tools.assert_equal(len(func.ret_sites), 0)
    nose.tools.assert_equal(func.jump_sites, {0x84e5})
    nose.tools.assert_equal(func.endpoints, func.jump_sites)

if __name__ == '__main__':
    test_functions_view()
