import os
import angr
import nose

test_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../../binaries/tests'))
arches = {'i386', 'x86_64'}

def main():
    test_cfg_get_any_node()

def test_cfg_get_any_node():
    for arch in arches:
        run_cfg_get_any_node(arch)

def run_cfg_get_any_node(arch):
    test_file = os.path.join(test_location, arch, 'hello_world')
    proj = angr.Project(test_file, auto_load_libs=False)
    cfg = proj.analyses.CFGFast()

    for node1 in cfg.nodes():
        if node1.size == 0:
            node2 = cfg.get_any_node(addr=node1.addr, anyaddr=True)
            nose.tools.assert_is_not_none(node2)

if __name__ == "__main__":
    main()
