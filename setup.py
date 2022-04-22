# pylint: disable=missing-class-docstring
import glob
import os
import platform
import shutil
import subprocess
import sys
from distutils.command.build import build as st_build
from distutils.util import get_platform

import pkg_resources
from setuptools import Command, setup
from setuptools.command.develop import develop as st_develop
from setuptools.errors import LibError

if sys.platform == "darwin":
    library_file = "angr_native.dylib"
elif sys.platform in ("win32", "cygwin"):
    library_file = "angr_native.dll"
else:
    library_file = "angr_native.so"


def _build_native():
    try:
        import pyvex  # pylint:disable=unused-import,import-outside-toplevel
    except ImportError as e:
        raise LibError("You must install pyvex before building angr") from e

    try:
        import unicorn  # pylint:disable=unused-import,import-outside-toplevel
    except ImportError as e:
        raise LibError("You must install unicorn before building angr") from e

    env = os.environ.copy()
    env_data = (
        ("UNICORN_INCLUDE_PATH", "unicorn", "include"),
        ("UNICORN_LIB_PATH", "unicorn", "lib"),
        ("UNICORN_LIB_FILE", "unicorn", "lib\\unicorn.lib"),
        ("PYVEX_INCLUDE_PATH", "pyvex", "include"),
        ("PYVEX_LIB_PATH", "pyvex", "lib"),
        ("PYVEX_LIB_FILE", "pyvex", "lib\\pyvex.lib"),
    )
    for var, pkg, fnm in env_data:
        try:
            env[var] = pkg_resources.resource_filename(pkg, fnm)
        except KeyError:
            pass

    cmd1 = ["nmake", "/f", "Makefile-win"]
    cmd2 = ["gmake"]
    cmd3 = ["make"]
    for cmd in (cmd1, cmd2, cmd3):
        try:
            if subprocess.call(cmd, cwd="native", env=env) != 0:
                raise LibError("Unable to build angr_native")
            break
        except OSError:
            continue
    else:
        raise LibError("Unable to build angr_native")

    shutil.rmtree("angr/lib", ignore_errors=True)
    os.mkdir("angr/lib")
    shutil.copy(os.path.join("native", library_file), "angr/lib")


def _clean_native():
    oglob = glob.glob("native/*.o")
    oglob += glob.glob("native/*.obj")
    oglob += glob.glob("native/*.so")
    oglob += glob.glob("native/*.dll")
    oglob += glob.glob("native/*.dylib")
    for fname in oglob:
        os.unlink(fname)


class build(st_build):
    def run(self, *args):
        self.execute(_build_native, (), msg="Building angr_native")
        super().run(*args)


class clean_native(Command):
    user_options = []

    def initialize_options(self):
        pass

    def finalize_options(self):
        pass

    def run(self):
        self.execute(_clean_native, (), msg="Cleaning angr_native")


class develop(st_develop):
    def run(self):
        self.run_command("build")
        super().run()


cmdclass = {
    "build": build,
    "clean_native": clean_native,
    "develop": develop,
}

if 'bdist_wheel' in sys.argv and '--plat-name' not in sys.argv:
    sys.argv.append('--plat-name')
    name = get_platform()
    if 'linux' in name:
        sys.argv.append('manylinux2014_' + platform.machine())
    else:
        # https://www.python.org/dev/peps/pep-0425/
        sys.argv.append(name.replace('.', '_').replace('-', '_'))

setup(cmdclass=cmdclass)
