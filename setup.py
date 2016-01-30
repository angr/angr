import os
import sys
import urllib2
import subprocess
from setuptools import setup
from setuptools.distutils.errors import LibError
import setuptools.command.build as _build
import setuptools.command.develop as _develop

UNICORN_PATH = 'unicorn'

def _build_unicorn():
    global UNICORN_PATH

    if not os.path.exists(UNICORN_PATH):
        UNICORN_URL = 'https://github.com/unicorn-engine/unicorn/archive/0.9.tar.gz'
        with open('unicorn-0.9.tar.gz', 'w') as v:
            v.write(urllib2.urlopen(UNICORN_URL).read())
        if subprocess.call(['tar', 'xzf', 'unicorn-0.9.tar.gz']) != 0:
            raise LibError('Unable to retrieve unicorn')
        UNICORN_PATH = 'unicorn-0.9'

    if subprocess.call(['make', cwd=UNICORN_PATH]) != 0:
        raise LibError('Unable to compile libunicorn')

    if subprocess.call(['make', 'install'], cwd=os.path.join(UNICORN_PATH, 'bindings', 'python')) != 0:
        raise LibError('Unable to install python bindings of unicorn')

def _build_sim_unicorn():
    env = os.environ.copy()
    env['UNICORN_PATH'] = os.path.join('..', UNICORN_PATH)
    if subprocess.call(['make'], cwd='simuvex_c', env=env) != 0:
        raise LibError('Unable to build sim_unicorn')

class build(_build):
    def run(self):
        try:
            self.execute(_build_unicorn, (), msg='Building libunicorn')
            self.execute(_build_sim_unicorn, (), msg='Building sim_unicorn')
        except LibError:
            pass
        _build.run(self)

class develop(_develop):
    def run(self):
        try:
            self.execute(_build_unicorn, (), msg='Building libunicorn')
            self.execute(_build_sim_unicorn, (), msg='Building sim_unicorn')
        except LibError:
            pass
        _develop.run(self)

cmdclass = {
        'build': build,
        'develop': develop,
        }

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
)
