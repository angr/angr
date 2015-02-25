#!/usr/bin/env python

import nose
import logging
import angr
import os

logging.basicConfig(level=logging.INFO)
test_location = str(os.path.dirname(os.path.realpath(__file__)))

def prepare_mipsel():
    ping = os.path.join(test_location, "blob/mipsel/darpa_ping")
    skip=['libgcc_s.so.1', 'libresolv.so.0']
    ops= {"except_on_ld_fail": False, 'skip_libs': skip, 'auto_load_libs':True}
    load_options={}
    load_options[ping] = dict(ops.items() + {'backend': 'elf'}.items())
    p = angr.Project(ping, load_options=load_options)
    return p

def prepare_ppc():
    libc = os.path.join(test_location, "blob/ppc/libc.so.6")
    p = angr.Project(libc, load_options={'auto_load_libs':True})
    return p

def test_ppc(p):
    # This tests the relocation of _rtld_global_ro in ppc libc6.
    # This relocation is of type 20, and relocates a non-local symbol
    relocated = p.ld.memory.read_addr_at(0x18ace4, p.main_binary.archinfo)
    nose.tools.assert_equal(relocated, 0xf666e320)



def test_mipsel(p):
    dep = p.ld.dependencies

    # 1) check dependencies and loaded binaries
    nose.tools.assert_equal(dep, {'libresolv.so.0': 0, 'libgcc_s.so.1': 0, 'libc.so.6': 0})
    #nose.tools.assert_equal(p.ld.shared_objects[0].binary, '/usr/mipsel-linux-gnu/lib/libc.so.6')
    nose.tools.assert_true('libc.so.6' in p.ld.shared_objects[0].binary)

    # cfg = p.construct_cfg()
    # nodes = cfg.get_nodes()

    # Get the address of simprocedure __uClibc_main
    sproc_addr = 0
    s_name = "<class 'simuvex.procedures.libc___so___6.__uClibc_main.__uClibc_main'>"
    for k,v in p.sim_procedures.iteritems():
        if str(v[0]) == s_name:
            sproc_addr = k
    nose.tools.assert_false(sproc_addr == 0)

    # 2) Check GOT slot containts the right address
    # Cle: 4494036
    got = p.ld.find_symbol_got_entry('__uClibc_main')
    addr = p.ld.memory.read_addr_at(got, p.main_binary.archinfo)
    nose.tools.assert_equal(addr, sproc_addr)

    ioctl = p.ld.find_symbol_got_entry("ioctl")
    setsockopt = p.ld.find_symbol_got_entry("setsockopt")

    nose.tools.assert_equal(ioctl, 4494300)
    nose.tools.assert_equal(setsockopt, 4494112)

if __name__ == "__main__":
    e = prepare_mipsel()
    test_mipsel(e)

    e = prepare_ppc()
    test_ppc(e)
