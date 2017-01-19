# pylint: disable=no-name-in-module,import-error,unused-variable
import os
import sys
import subprocess
import pkg_resources
import shutil
import platform

try:
    from setuptools import setup
    from setuptools import find_packages
    packages = find_packages()
except ImportError:
    from distutils.core import setup
    packages = [x.strip('./').replace('/','.') for x in os.popen('find -name "__init__.py" | xargs -n1 dirname').read().strip().split('\n')]

from distutils.util import get_platform
from distutils.errors import LibError
from distutils.command.build import build as _build

if sys.platform == 'darwin':
    library_file = "sim_unicorn.dylib"
elif sys.platform in ('win32', 'cygwin'):
    library_file = "sim_unicorn.dll"
else:
    library_file = "sim_unicorn.so"

def _build_sim_unicorn():
    try:
        import unicorn
        import pyvex
    except ImportError:
        raise LibError("You must install unicorn and pyvex before building simuvex")

    env = os.environ.copy()
    env_data = (('UNICORN_INCLUDE_PATH', 'unicorn', 'include'),
                ('UNICORN_LIB_PATH', 'unicorn', 'lib'),
                ('UNICORN_LIB_FILE', 'unicorn', 'lib\\unicorn.lib'),
                ('PYVEX_INCLUDE_PATH', 'pyvex', 'include'),
                ('PYVEX_LIB_PATH', 'pyvex', 'lib'),
                ('PYVEX_LIB_FILE', 'pyvex', 'lib\\pyvex.lib'))
    for var, pkg, fnm in env_data:
        try:
            env[var] = pkg_resources.resource_filename(pkg, fnm)
        except KeyError:
            pass

    cmd1 = ['nmake', '/f', 'Makefile-win']
    cmd2 = ['make']
    for cmd in (cmd1, cmd2):
        try:
            if subprocess.call(cmd, cwd='simuvex_c', env=env) != 0:
                raise LibError('Unable to build sim_unicorn')
            break
        except OSError:
            continue
    else:
        raise LibError('Unable to build sim_unicorn')

    shutil.rmtree('simuvex/lib', ignore_errors=True)
    os.mkdir('simuvex/lib')
    shutil.copy(os.path.join('simuvex_c', library_file), 'simuvex/lib')

class build(_build):
    def run(self, *args):
        self.execute(_build_sim_unicorn, (), msg='Building sim_unicorn')
        _build.run(self, *args)

cmdclass = {
    'build': build,
}

try:
    from setuptools.command.develop import develop as _develop
    class develop(_develop):
        def run(self, *args):
            self.execute(_build_sim_unicorn, (), msg='Building sim_unicorn')
            _develop.run(self, *args)

    cmdclass['develop'] = develop
except ImportError:
    pass

if 'bdist_wheel' in sys.argv and '--plat-name' not in sys.argv:
    sys.argv.append('--plat-name')
    name = get_platform()
    if 'linux' in name:
        # linux_* platform tags are disallowed because the python ecosystem is fubar
        # linux builds should be built in the centos 5 vm for maximum compatibility
        sys.argv.append('manylinux1_' + platform.machine())
    else:
        # https://www.python.org/dev/peps/pep-0425/
        sys.argv.append(name.replace('.', '_').replace('-', '_'))

setup(
    name='simuvex',
    version='6.7.1.13.post2',
    description=' A symbolic execution engine for the VEX IR',
    url='https://github.com/angr/simuvex',
    packages=packages,
    install_requires=[
        'bintrees',
        'cachetools',
        'enum34',
        'dpkt-fix',
        'pyvex',
        'archinfo',
        'claripy',
        'cooldict',
        'ana',
        'unicorn'
    ],
    setup_requires=['unicorn', 'pyvex'],
    cmdclass=cmdclass,
    include_package_data=True,
    package_data={
        'simuvex': ['lib/*']
    }
)
