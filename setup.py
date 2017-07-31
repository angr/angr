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
    library_file = "angr_native.dylib"
elif sys.platform in ('win32', 'cygwin'):
    library_file = "angr_native.dll"
else:
    library_file = "angr_native.so"

def _build_native():
    try:
        import unicorn
        import pyvex
    except ImportError:
        raise LibError("You must install unicorn and pyvex before building angr")

    env = os.environ.copy()
    env_data = (('UNICORN_INCLUDE_PATH', 'unicorn', 'include'),
                ('UNICORN_LIB_PATH', 'unicorn', 'lib'),
                ('UNICORN_LIB_FILE', 'unicorn', 'lib\\unicorn.lib'),
                ('PYVEX_INCLUDE_PATH', 'pyvex', 'include'),
                ('PYVEX_LIB_PATH', 'pyvex', 'lib'),
                ('PYVEX_LIB_FILE', 'pyvex', 'lib\\pyvex.lib'))
    for var, pkg, fnm in env_data:
        try:
            env[var] = pkg_resources.resource_filename(pkg, fnm).encode('ascii', 'ignore')
        except KeyError:
            pass

    cmd1 = ['nmake', '/f', 'Makefile-win']
    cmd2 = ['make']
    for cmd in (cmd1, cmd2):
        try:
            if subprocess.call(cmd, cwd='native', env=env) != 0:
                raise LibError('Unable to build angr_native')
            break
        except OSError:
            continue
    else:
        raise LibError('Unable to build angr_native')

    shutil.rmtree('angr/lib', ignore_errors=True)
    os.mkdir('angr/lib')
    shutil.copy(os.path.join('native', library_file), 'angr/lib')

class build(_build):
    def run(self, *args):
        self.execute(_build_native, (), msg='Building angr_native')
        _build.run(self, *args)

cmdclass = {
    'build': build,
}

try:
    from setuptools.command.develop import develop as _develop
    class develop(_develop):
        def run(self, *args):
            self.execute(_build_native, (), msg='Building angr_native')
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
    name='angr',
    version='6.7.6.9',
    description='The next-generation binary analysis/exploitation/rewriting/craziness framework!',
    url='https://github.com/angr/angr',
    packages=packages,
    install_requires=[
        'ana',
        'bintrees',
        'cachetools',
        'capstone',
        'cooldict',
        'dpkt-fix',
        'futures',
        'mulpyplexer',
        'networkx',
        'progressbar',
        'rpyc',
        'cffi>=1.7.0',
        'unicorn',
        'archinfo>=6.7.6.9',
        'claripy>=6.7.6.9',
        'cle>=6.7.6.9',
        'pyvex>=6.7.6.9',
    ],
    setup_requires=['unicorn', 'pyvex'],
    cmdclass=cmdclass,
    include_package_data=True,
    package_data={
        'angr': ['lib/*']
    }
)
