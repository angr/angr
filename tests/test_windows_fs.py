import nose.tools

import angr
from angr.state_plugins.filesystem import SimFilesystem

import logging
l = logging.getLogger('angr.tests.test_windows_fs')

from os import path

test_location = path.join(path.dirname(path.realpath(__file__)), '..', '..', 'binaries', 'tests')


def test_fs_support():
    binary_path = path.join(test_location, 'i386', 'simple_windows.exe')
    proj = angr.Project(binary_path, auto_load_libs=False)
    hello_txt = angr.SimFile(b'hello.txt', content=b'hello')

    state = proj.factory.entry_state(fs={b'C:\\hello.txt': hello_txt})
    nose.tools.assert_is_instance(state.fs, SimFilesystem)
    nose.tools.assert_equal(state.fs.get(b'C:\\hello.txt'), hello_txt)
