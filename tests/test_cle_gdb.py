import angr
import os
import nose

test_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                 '../../binaries/tests'))

def test_cle_gdb():
    binpath = os.path.join(test_location, "x86_64/test_gdb_plugin")
    mappath = os.path.join(test_location, "../test_data/test_gdb_plugin/procmap")
    p = angr.Project(binpath, load_options={"gdb_map":mappath})

    libc = p.loader.shared_objects['libc.so.6']
    ld = p.loader.shared_objects['ld-linux-x86-64.so.2']
    nose.tools.assert_equal(libc.rebase_addr, 0x7ffff7a17000)
    nose.tools.assert_equal(ld.rebase_addr, 0x7ffff7ddc000)

if __name__ == "__main__":
    test_cle_gdb()
