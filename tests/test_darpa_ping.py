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


def _test(p):
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

    byt = p.ld.read_bytes(got, p.main_binary.archinfo.bits/8)
    fmt = p.main_binary.archinfo.get_struct_fmt()
    addr = int(struct.unpack(fmt, "".join(byt))[0])

    nose.tools.assert_equal(addr, sproc_addr)

def ida_test(p):

    _test(p)

    ioctl = p.ld.find_symbol_got_entry("ioctl")
    setsockopt = p.ld.find_symbol_got_entry("setsockopt")

    nose.tools.assert_equal(ioctl, 4573300L)
    nose.tools.assert_equal(setsockopt, 4573200L)


def elf_test(p):

    _test(p)

    ioctl = p.ld.find_symbol_got_entry("ioctl")
    setsockopt = p.ld.find_symbol_got_entry("setsockopt")

    nose.tools.assert_equal(ioctl, 4494300)
    nose.tools.assert_equal(setsockopt, 4494112)


if __name__ == "__main__":
    e = prepare_elf()
    elf_test(e)

    i = prepare_ida()
    ida_test(i)

