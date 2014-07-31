#!/usr/bin/env python

import nose
import logging
l = logging.getLogger("angr.tests")

try:
    # pylint: disable=W0611,F0401
    import standard_logging
    import angr_debug
except ImportError:
    pass

import angr, simuvex

# load the tests
import os
test_location = str(os.path.dirname(os.path.realpath(__file__)))
fauxware_x86 = None
fauxware_amd64 = None
fauxware_ppc32 = None
fauxware_arm = None
fauxware_mipsel = None

def setup_x86():
    global fauxware_x86
    fauxware_x86 = angr.Project(test_location + "/fauxware/fauxware-x86", load_libs=False, default_analysis_mode='symbolic', use_sim_procedures=True, arch="X86")
def setup_amd64():
    global fauxware_amd64
    fauxware_amd64 = angr.Project(test_location + "/fauxware/fauxware-amd64", load_libs=False, default_analysis_mode='symbolic', use_sim_procedures=True, arch="AMD64")
def setup_ppc32():
    global fauxware_ppc32
    fauxware_ppc32 = angr.Project(test_location + "/fauxware/fauxware-ppc32", load_libs=False, default_analysis_mode='symbolic', use_sim_procedures=True, arch="PPC32")
def setup_mipsel():
    global fauxware_mipsel
    fauxware_mipsel = angr.Project(test_location + "/fauxware/fauxware-mipsel", load_libs=False, default_analysis_mode='symbolic', use_sim_procedures=True, arch=simuvex.SimMIPS32(endness="Iend_LE"))
def setup_arm():
    global fauxware_arm
    fauxware_arm = angr.Project(test_location + "/fauxware/fauxware-arm", load_libs=False, default_analysis_mode='symbolic', use_sim_procedures=True, arch=simuvex.SimARM(endness="Iend_LE"))

def setup_module():
    setup_x86()
    setup_amd64()
    setup_arm()
    setup_ppc32()
    setup_mipsel()

def test_x86():
    raise Exception("Not implemented.")

def test_amd64():
    cfg = angr.CFG()
    cfg.construct(fauxware_amd64.binaries["fauxware-amd64"], fauxware_amd64)
    import ipdb; ipdb.set_trace()
    func_man = cfg.get_function_manager()
    functions = func_man.functions
    l.info(functions)
    # TODO: Check the result returned
    func_man.dbg_draw()
    l.info("PNG files generated.")

def test_ppc32():
    raise Exception("Not implemented.")

def test_arm():
    raise Exception("Not implemented.")

def test_mipsel():
    raise Exception("Not implemented.")

if __name__ == "__main__":
    setup_amd64()
    l.info("LOADED")
    test_amd64()
    l.info("DONE")
