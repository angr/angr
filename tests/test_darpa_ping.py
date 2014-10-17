#!/usr/bin/env python

import nose
import logging
import angr
import os
import struct

logging.basicConfig(level=logging.INFO)

test_location = str(os.path.dirname(os.path.realpath(__file__)))
ping = os.path.join(test_location, "blob/mipsel/darpa_ping")
skip=['libgcc_s.so.1', 'libresolv.so.0']

def prepare_ida():
    load_options = {}
    load_options[ping] = {"except_on_ld_fail": False, 'skip_libs': skip, 'backend':'ida'}
    p = angr.Project(ping, load_options=load_options)
    return p

def prepare_elf():
    load_options = {}
    load_options[ping] = {"except_on_ld_fail": False, 'skip_libs': skip, 'backend':'elf'}
    p = angr.Project(ping, load_options=load_options)
    return p


def test_elf():
    p = prepare_elf()
    dep = p.ld.dependencies
    #c_dep = p.ld._custom_dependencies

    # 1) check dependencies and loaded binaries
    nose.tools.assert_equal(dep, {'libresolv.so.0': 0, 'libgcc_s.so.1': 0, 'libc.so.6': 0})
    nose.tools.assert_equal(p.ld.shared_objects[0].binary, '/usr/mipsel-linux-gnu/lib/libc.so.6')

    ioctl = p.ld.find_symbol_got_entry("ioctl")
    setsockopt = p.ld.find_symbol_got_entry("setsockopt")

    nose.tools.assert_equal(ioctl, 4494300)
    nose.tools.assert_equal(setsockopt, 4494112)

    # cfg = p.construct_cfg()
# nodes = cfg.get_nodes()
# n = nodes[0]
# out = 'ld-uClibc.so.6' in p.sim_procedures

    # Get the address of simprocedure __uClibc_main
    sproc_addr = 0
    for k,v in p.sim_procedures.iteritems():
        if str(v[0]) == "<class '__uClibc_main.__uClibc_main'>":
            sproc_addr = k
    nose.tools.assert_false(sproc_addr == 0)

    # 2) Check GOT slot containts the right address
    # Cle: 4494036
    got = p.ld.main_bin.jmprel['__uClibc_main']

    byt = p.ld.read_bytes(got, p.main_binary.archinfo.bits/8)
    fmt = p.main_binary.archinfo.get_struct_fmt()
    addr = int(struct.unpack(fmt, "".join(byt))[0])

    nose.tools.assert_equal(addr, sproc_addr)

def test_ida():
    p = prepare_ida()
    im = p.ld.main_bin.imports
    import pdb; pdb.set_trace()
    #got = p.ld.main_bin.jmprel['__uClibc_main']



if __name__ == "__main__":
    test_ida()
