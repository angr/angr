# pylint: disable=no-name-in-module,import-error,unused-variable
import os
import sys
import subprocess
import pkg_resources
import shutil
import platform
import glob

if bytes is str:
    raise Exception("""

=-=-=-=-=-=-=-=-=-=-=-=-=  WELCOME TO THE FUTURE!  =-=-=-=-=-=-=-=-=-=-=-=-=-=

angr has transitioned to python 3. Due to the small size of the team behind it,
we can't reasonably maintain compatibility between both python 2 and python 3.
If you want to continue using the most recent version of angr (you definitely
want that, trust us) you should upgrade to python 3. It's like getting your
vaccinations. It hurts a little bit initially but in the end it's worth it.

If you are staying on python 2 and would like to make sure you don't get
incompatible versions, make sure your pip is at least version 9.0, and it will
use our metadata to implicitly avoid them.

For more information, see here: https://docs.angr.io/appendix/migration

Good luck!
""")

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
from distutils.command.clean import clean as _clean

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
            env[var] = pkg_resources.resource_filename(pkg, fnm)
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

def _clean_native():
    oglob  = glob.glob('native/*.o')
    oglob += glob.glob('native/*.obj')
    oglob += glob.glob('native/*.so')
    oglob += glob.glob('native/*.dll')
    oglob += glob.glob('native/*.dylib')
    for fname in oglob:
        os.unlink(fname)

class build(_build):
    def run(self, *args):
        self.execute(_build_native, (), msg='Building angr_native')
        _build.run(self, *args)

class clean(_clean):
    def run(self, *args):
        self.execute(_clean_native, (), msg='Cleaning angr_native')
        _clean.run(self, *args)

cmdclass = {
    'build': build,
    'clean': clean,
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

_UNICORN = "unicorn>=1.0.2rc2"

setup(
    name='angr',
    version='8.20.6.1',
    python_requires='>=3.6',
    description='A multi-architecture binary analysis toolkit, with the ability to perform dynamic symbolic execution and various static analyses on binaries',
    url='https://github.com/angr/angr',
    packages=packages,
    install_requires=[
        'sortedcontainers',
        'cachetools',
        'capstone>=3.0.5rc2',
        'dpkt',
        'mulpyplexer',
        'networkx>=2.0',
        'progressbar2',
        'rpyc',
        'cffi>=1.7.0',
        _UNICORN,
        'archinfo==8.20.6.1',
        'claripy==8.20.6.1',
        'cle==8.20.6.1',
        'pyvex==8.20.6.1',
        'ailment==8.20.6.1',
        'GitPython',
        'psutil',
        'pycparser>=2.18',
        'itanium_demangler',
        'protobuf',
    ],
    setup_requires=[_UNICORN, 'pyvex'],
    extras_require={
        'AngrDB': ['sqlalchemy'],
    },
    cmdclass=cmdclass,
    include_package_data=True,
    package_data={
        'angr': ['lib/*', "py.typed"]
    }
)
