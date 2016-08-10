# pylint: disable=no-name-in-module,import-error
import os
import subprocess
from setuptools import setup
from distutils.errors import LibError
from distutils.command.build import build as _build

def _build_sim_unicorn():
    try:
        import unicorn
    except ImportError:
        raise LibError("You must install unicorn before building simuvex")

    uc_path = os.path.join(os.path.dirname(unicorn.__file__), '../../..')
    env = os.environ.copy()
    env['UNICORN_PATH'] = uc_path
    if subprocess.call(['make'], cwd='simuvex_c', env=env) != 0:
        raise LibError('Unable to build sim_unicorn')

class build(_build):
    def run(self, *args):
        try:
            self.execute(_build_sim_unicorn, (), msg='Building sim_unicorn')
            data_files.append(('lib', (os.path.join('simuvex_c', 'sim_unicorn.so'),),))
        except LibError:
            print 'Failed to build unicorn engine support'
        _build.run(self, *args)

from setuptools.command.develop import develop as _develop
class develop(_develop):
    def run(self, *args):
        try:
            self.execute(_build_sim_unicorn, (), msg='Building sim_unicorn')
            data_files.append(('lib', (os.path.join('simuvex_c', 'sim_unicorn.so'),),))
        except LibError:
            pass
        _develop.run(self, *args)

cmdclass = {
        'build': build,
        'develop': develop,
}
data_files = []

setup(
    name='simuvex',
    version='4.6.6.28',
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
    data_files=data_files,
    cmdclass=cmdclass,
)
