#!/usr/bin/env python

import os
import logging
import time

l = logging.getLogger("angr_tests")

import nose.tools

try:
    import standard_logging
    import angr_debug
except ImportError:
    pass

import angr

test_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../../binaries/tests'))

vfg_0_addresses = {
    'x86_64': 0x40055c
}

def run_vfg_0(arch):
    proj = angr.Project(os.path.join(os.path.join(test_location, arch), "basic_buffer_overflows"),
                 use_sim_procedures=True,
                 default_analysis_mode='symbolic')

    """
    import ana
    import pickle

    # setup datalayer so that we can pickle CFG
    ana.set_dl(pickle_dir="/tmp")
    cfg_dump_filename = "/tmp/test_vfg_0_%s.cfg_dump" % arch

    cfg_loaded = False
    while not cfg_loaded:
        if os.path.isfile(cfg_dump_filename):
            try:
                cfg = pickle.load(open(cfg_dump_filename, "rb"))
                cfg_loaded = True

            except Exception:
                os.remove(cfg_dump_filename)

        else:
            cfg = proj.analyses.CFG(context_sensitivity_level=1)
            pickle.dump(cfg, open(cfg_dump_filename, "wb"))

            cfg_loaded = True
    """
    cfg = proj.analyses.CFG(context_sensitivity_level=1)

    start = time.time()
    function_start = vfg_0_addresses[arch]
    vfg = proj.analyses.VFG(cfg, function_start=function_start, context_sensitivity_level=2, interfunction_level=4)
    end = time.time()
    duration = end - start

    l.info("VFG generation done in %f seconds." % duration)

    # TODO: These are very weak conditions. Make them stronger!
    nose.tools.assert_greater(len(vfg.result['final_states']), 0)
    se = vfg.result['final_states'][-1].se
    nose.tools.assert_true(se.is_true(vfg.result['final_states'][-1].stack_read(12, 4) >= 0x28))

def test_vfg_0():
    for arch in vfg_0_addresses:
        yield run_vfg_0, arch

if __name__ == "__main__":
    import sys
    # logging.getLogger("simuvex.plugins.abstract_memory").setLevel(logging.DEBUG)
    # logging.getLogger("simuvex.plugins.symbolic_memory").setLevel(logging.DEBUG)
    logging.getLogger("angr.analyses.cfg").setLevel(logging.DEBUG)
    logging.getLogger("angr.analyses.vfg").setLevel(logging.DEBUG)
    # Temporarily disable the warnings of claripy backend
    logging.getLogger("claripy.backends.backend").setLevel(logging.ERROR)
    logging.getLogger("claripy.claripy").setLevel(logging.ERROR)

    if len(sys.argv) > 1:
        func_name = 'test_' + sys.argv[1]
        if func_name in globals() and hasattr(globals()[func_name], '__call__'):
            f = globals()[func_name]
            for func, arch in f():
                func(arch)

        else:
            raise ValueError('Function %s does not exist' % func_name)

    else:
        g = globals()
        for func_name, f in g.items():
            if func_name.startswith('test_') and hasattr(f, '__call__'):
                for func, arch in f():
                    func(arch)
