import angr
import os
import nose

test_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                 '../../binaries/tests'))
binpath = os.path.join(test_location, "x86_64/test_gdb_plugin")

def check_addrs(p):
    libc = p.loader.shared_objects['libc.so.6']
    ld = p.loader.shared_objects['ld-linux-x86-64.so.2']
    nose.tools.assert_equal(libc.mapped_base, 0x7ffff7a17000)
    nose.tools.assert_equal(ld.mapped_base, 0x7ffff7ddc000)

def test_cle_gdb():
    """
    Test for `info proc mappings`
    """
    mappath = os.path.join(test_location, "../test_data/test_gdb_plugin/procmap")
    p = angr.Project(binpath, load_options={"gdb_map":mappath})
    check_addrs(p)

def test_sharedlibs():
    """
    Test for info sharedlibrary
    """
    mappath = os.path.join(test_location, "../test_data/test_gdb_plugin/info_sharedlibs")
    p = angr.Project(binpath, load_options={"gdb_map":mappath, "gdb_fix":True})
    check_addrs(p)

if __name__ == "__main__":
    test_cle_gdb()
    test_sharedlibs()
