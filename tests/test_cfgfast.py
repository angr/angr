
import os
import logging

import nose.tools

import angr

l = logging.getLogger("angr.tests.test_cfgfast")

import os
test_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../../binaries/tests'))

def cfg_fast(arch, binary_path, func_addrs):
    """
    Generate a CFGFast analysis result on the given binary, and test if all specified functions are found

    :param arch: the architecture, will be prepended to `binary_path`
    :param binary_path: path to the binary under the architecture directory
    :param func_addrs: A collection of function addresses that should be recovered
    :return: None
    """

    path = os.path.join(test_location, arch, binary_path)
    proj = angr.Project(path, load_options={'auto_load_libs': False})

    cfg = proj.analyses.CFGFast()

    function_manager = cfg.function_manager

    nose.tools.assert_true(set(function_manager.functions.keys()).issuperset(func_addrs))

def test_cfg_0():
    filename = 'cfg_0'
    functions = {
        'x86_64': {
            0x400410,
            0x400420,
            0x400430,
            0x400440,
            0x400470,
            0x40052c,
            0x40053c,
        }
    }
    arches = functions.keys()

    for arch in arches:
        yield cfg_fast, arch, filename, functions[arch]

def main():
    for func, arch, filename, functions in test_cfg_0():
        func(arch, filename, functions)

if __name__ == "__main__":
    main()
