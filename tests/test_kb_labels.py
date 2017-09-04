import nose
import angr
import networkx

import os
location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../../binaries/tests'))


def test_kb_plugins():
    labels = angr.knowledge_plugins.LabelsPlugin(None)
    
    # Use default namespace for tests
    ns = labels.get_namespace()

    # Basic tests
    ns.set_label(0, 'zero')
    nose.tools.assert_equal(ns.get_name(0), 'zero')
    nose.tools.assert_equal(ns.get_all_names(0), ['zero'])
    nose.tools.assert_equal(ns.get_addr('zero'), 0)

    ns.del_name('zero')
    nose.tools.assert_equal(ns.get_all_names(0), [])

    # Test accessors
    ns[1] = 'one'
    ns[2] = 'two'
    ns[3] = 'three'
    nose.tools.assert_equal(ns[1], 'one')
    nose.tools.assert_in(1, ns)
    nose.tools.assert_equal(set(ns), {'one', 'two', 'three'})

    del ns[3]
    nose.tools.assert_equal(set(ns), {'one', 'two'})

    # Test alternative names
    ns.set_label(0x1000, 'label1')
    ns.set_label(0x1000, 'label1_alt')
    nose.tools.assert_equal(ns.get_name(0x1000), 'label1')
    nose.tools.assert_not_equal(ns.get_name(0x1000), 'label1_alt')
    nose.tools.assert_in('label1_alt', ns.get_all_names(0x1000))

    ns.set_label(0x1000, 'label1_2', make_default=True)
    nose.tools.assert_equal(ns.get_name(0x1000), 'label1_2')

    # Test overwriting existing labels
    ns.set_label(0x2000, 'label1')
    nose.tools.assert_equal(ns.get_name(0x2000), 'label1')
    nose.tools.assert_not_equal(ns.get_name(0x1000), 'label1')

    ns.set_label(0x3000, 'label1', dup_mode='suffix')
    nose.tools.assert_equal(ns.get_name(0x3000), 'label1_0')
    nose.tools.assert_equal(ns.get_name(0x2000), 'label1')

    # Test separate namespaces
    labels.add_namespace('foo')
    ns_foo = labels.get_namespace('foo')

    ns_foo.set_label(0x4000, 'label1')
    nose.tools.assert_not_equal(ns.get_addr('label1'), ns_foo.get_addr('label1'))

    # Test with project
    p = angr.Project(location + "/x86_64/fauxware", auto_load_libs=False)
    labels = p.kb.labels

if __name__ == '__main__':
    test_kb_plugins()
