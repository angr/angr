import nose
import angr
import networkx

import os
location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../../binaries/tests'))


def test_kb_plugins():
    p = angr.Project(location + "/x86_64/fauxware")
    labels = p.kb.labels

    labels.set_label(0x1000, 'label1', 'foo')
    labels.set_label(0x2000, 'label2', 'foo')
    labels.set_label(0x1000, 'label2', 'bar')
    labels.set_label(0x2000, 'label1', 'bar')

    with nose.tools.assert_raises(ValueError):
        labels.set_label(0x3000, 'label1', 'foo')

    with nose.tools.assert_raises(ValueError):
        labels.set_label(0x2000, 'label3', 'bar')

    nose.tools.assert_equal(labels.get_label(0x1000, 'foo'), 'label1')
    nose.tools.assert_equal(labels.get_label(0x1000, 'bar'), 'label2')
    nose.tools.assert_equal(labels.get_label(0x2000, 'foo'), 'label2')
    nose.tools.assert_equal(labels.get_label(0x2000, 'bar'), 'label1')

    nose.tools.assert_is_none(labels.get_label(0x1000))
    nose.tools.assert_is_not_none(labels.get_label(0x1000, default=True))

    nose.tools.assert_equal(set(labels.iter_labels(0x1000)),
                            {('foo', 'label1'), ('bar', 'label2'), ('', 'lbl_1000')})

    # Compat checks.
    for name in labels:
        addr = labels[name]
        nose.tools.assert_is_instance(name, (str, unicode, bytes))
        nose.tools.assert_is_instance(addr, (int, long))

    # Copy check. 
    labels_copy = labels.copy()
    nose.tools.assert_equal(labels._namespaces, labels_copy._namespaces)

if __name__ == '__main__':
    test_kb_plugins()
