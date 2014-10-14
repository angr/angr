#!/usr/bin/env python

import nose
import logging
import angr
import os

logging.basicConfig(level=logging.WARNING)


if __name__ == "__main__":
    load_options = {}
    test_location = str(os.path.dirname(os.path.realpath(__file__)))
    ping = os.path.join(test_location, "blob/mipsel/darpa_ping")
    skip=['libgcc_s.so.1', 'libresolv.so.0']

    load_options[ping] = {"except_on_ld_fail": False, 'skip_libs': skip}
    p = angr.Project(ping, load_options=load_options)
    cfg = p.construct_cfg()

    dep = p.ld.dependencies
    c_dep = p.ld._custom_dependencies

    # Dependencies and loaded binaries
    nose.tools.assert_equal(dep, {'libresolv.so.0': 0, 'libgcc_s.so.1': 0, 'libc.so.6': 0})
    nose.tools.assert_equal(p.ld.shared_objects[0].binary, '/usr/mipsel-linux-gnu/lib/libc.so.6')

    ioctl = p.ld.find_symbol_got_entry("ioctl")
    setsockopt = p.ld.find_symbol_got_entry("setsockopt")

    nose.tools.assert_equal(ioctl, 4494300)
    nose.tools.assert_equal(setsockopt, 4494112)

    nodes = cfg.get_nodes()
