import os
import subprocess
from setuptools import setup
from distutils.errors import LibError
from distutils.command.build import build as _build

def _build_unicorn():
    try:
        import unicorn #pylint:disable=unused-import,unused-variable
    except ImportError:
        if subprocess.call(['./install-unicorn.sh']) != 0:
            raise LibError('Unable to install unicorn')

def _build_sim_unicorn():
    env = os.environ.copy()
    env['UNICORN_PATH'] = '../unicorn'
    if subprocess.call(['make'], cwd='simuvex_c', env=env) != 0:
        raise LibError('Unable to build sim_unicorn')

class build(_build):
    def run(self, *args):
        try:
            self.execute(_build_unicorn, (), msg='Building libunicorn')
            self.execute(_build_sim_unicorn, (), msg='Building sim_unicorn')
            data_files.append(('lib', (os.path.join('simuvex_c', 'sim_unicorn.so'),),))
        except LibError:
            pass
        _build.run(self, *args)

from setuptools.command.develop import develop as _develop
class develop(_develop):
    def run(self, *args):
        try:
            self.execute(_build_unicorn, (), msg='Building libunicorn')
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
    packages=['simuvex', 'simuvex.plugins', 'simuvex.storage', 'simuvex.vex', 'simuvex.vex.statements', 'simuvex.vex.expressions', 'simuvex.procedures', 'simuvex.procedures.cgc', 'simuvex.procedures.ld-linux-x86-64___so___2', 'simuvex.procedures.testing', 'simuvex.procedures.stubs', 'simuvex.procedures.syscalls', 'simuvex.procedures.ld-uClibc___so___0', 'simuvex.procedures.libc___so___6'],
    install_requires=[
        'bintrees',
        'dpkt-fix',
        'pyvex',
        'archinfo',
        'claripy',
        'cooldict',
        'ana',
    ],
    data_files=data_files,
    cmdclass=cmdclass,
)
