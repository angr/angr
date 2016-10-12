# pylint: disable=no-name-in-module,import-error
import os
import sys
import subprocess
import pkg_resources
import shutil
from setuptools import setup
from distutils.errors import LibError
from distutils.command.build import build as _build

if sys.platform == 'darwin':
    library_file = "sim_unicorn.dylib"
else:
    library_file = "sim_unicorn.so"

def _build_sim_unicorn():
    try:
        import unicorn
        import pyvex
    except ImportError:
        raise LibError("You must install unicorn and pyvex before building simuvex")

    env = os.environ.copy()
    env['UNICORN_LIB_PATH'] = pkg_resources.resource_filename('unicorn', 'lib')
    env['UNICORN_INCLUDE_PATH'] = pkg_resources.resource_filename('unicorn', 'include')
    env['PYVEX_LIB_PATH'] = pkg_resources.resource_filename('pyvex', 'lib')
    env['PYVEX_INCLUDE_PATH'] = pkg_resources.resource_filename('pyvex', 'include')
    if subprocess.call(['make'], cwd='simuvex_c', env=env) != 0:
        raise LibError('Unable to build sim_unicorn')

    shutil.rmtree('simuvex/lib', ignore_errors=True)
    os.mkdir('simuvex/lib')
    shutil.copy(os.path.join('simuvex_c', library_file), 'simuvex/lib')

class build(_build):
    def run(self, *args):
        try:
            self.execute(_build_sim_unicorn, (), msg='Building sim_unicorn')
        except LibError:
            print 'Failed to build unicorn engine support'
        _build.run(self, *args)

from setuptools.command.develop import develop as _develop
class develop(_develop):
    def run(self, *args):
        try:
            self.execute(_build_sim_unicorn, (), msg='Building sim_unicorn')
        except LibError:
            pass
        _develop.run(self, *args)

cmdclass = {
        'build': build,
        'develop': develop,
}

setup(
    name='simuvex',
    version='5.6.10.12',
    description=' A symbolic execution engine for the VEX IR',
    url='https://github.com/angr/simuvex',
    packages=['simuvex', 'simuvex.plugins', 'simuvex.storage', 'simuvex.vex', 'simuvex.vex.statements', 'simuvex.vex.expressions', 'simuvex.procedures', 'simuvex.procedures.cgc', 'simuvex.procedures.ld-linux-x86-64___so___2', 'simuvex.procedures.testing', 'simuvex.procedures.stubs', 'simuvex.procedures.syscalls', 'simuvex.procedures.ld-uClibc___so___0', 'simuvex.procedures.libc___so___6', 'simuvex.concretization_strategies'],
    install_requires=[
        'bintrees',
        'dpkt-fix',
        'pyvex',
        'archinfo',
        'claripy',
        'cooldict',
        'ana'
    ],
    cmdclass=cmdclass,
    include_package_data=True,
    package_data={
        'simuvex': ['lib/*']
    }
)
