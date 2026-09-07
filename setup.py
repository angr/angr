# pylint: disable=missing-class-docstring
from __future__ import annotations

import glob
import importlib
import importlib.resources
import importlib.util
import os
import shutil
import subprocess
import sys

import setuptools_rust
from distutils.command.build import build as st_build
from setuptools import Command, setup
from setuptools.command.develop import develop as st_develop
from setuptools.errors import LibError

if sys.platform == "darwin":
    library_file = "unicornlib.dylib"
elif sys.platform in ("win32", "cygwin"):
    library_file = "unicornlib.dll"
else:
    library_file = "unicornlib.so"

is_wasm_build = sys.platform == "emscripten" or os.environ.get("_PYTHON_HOST_PLATFORM", "").startswith("emscripten")


def build_unicornlib():
    try:
        importlib.import_module("pyvex")
    except ImportError as e:
        raise LibError("You must install pyvex before building angr") from e

    env = os.environ.copy()
    env_data = (
        ("PYVEX_INCLUDE_PATH", "pyvex", "include"),
        ("PYVEX_LIB_PATH", "pyvex", "lib"),
        ("PYVEX_LIB_FILE", "pyvex", "lib\\pyvex.lib"),
    )
    for var, pkg, fnm in env_data:
        base = importlib.resources.files(pkg)
        for child in fnm.split("\\"):
            base = base.joinpath(child)
        env[var] = str(base)

    if sys.platform == "win32":
        cmd = ["nmake", "/f", "Makefile-win"]
    elif shutil.which("gmake") is not None:
        cmd = ["gmake"]
    else:
        cmd = ["make"]
    try:
        subprocess.run(cmd, cwd="native/unicornlib", env=env, check=True)
    except FileNotFoundError as err:
        raise LibError("Couldn't find " + cmd[0] + " in PATH") from err
    except subprocess.CalledProcessError as err:
        raise LibError("Error while building unicornlib: " + str(err)) from err

    shutil.rmtree("angr/lib", ignore_errors=True)
    os.mkdir("angr/lib")
    shutil.copy(os.path.join("native/unicornlib", library_file), "angr")


def z3_loader():
    """angr/_z3.py, loaded out of the source tree: importing angr needs the extension we are building."""
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "angr", "_z3.py")
    spec = importlib.util.spec_from_file_location("angr_z3_loader", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def configure_z3():
    """Point the Rust build at the libz3 that ships in the z3-solver wheel.

    z3-sys probes pkg-config before honoring the override, and its search path would win, so a
    machine with a system-wide Z3 of another version would link that instead -- the bindings are
    tied to one Z3 release. Windows takes its import library from Z3's own release (see
    native/angr/Cargo.toml) and ignores both of these.

    A caller that already set Z3_LIBRARY_PATH_OVERRIDE has told us which libz3 to link, so do
    not consult the build interpreter: when cross-compiling, the z3-solver installed here is
    the host's and its libz3 is the wrong architecture entirely.
    """
    if "Z3_LIBRARY_PATH_OVERRIDE" not in os.environ:
        try:
            library_dir = z3_loader().library_dir()
        except ImportError as err:
            raise LibError("You must install z3-solver before building angr") from err

        os.environ["Z3_LIBRARY_PATH_OVERRIDE"] = str(library_dir)

    os.environ.setdefault("Z3_NO_PKG_CONFIG", "1")


def build_protos():
    proto_files = sorted(glob.glob("angr/protos/*.proto"))
    cmd = [sys.executable, "-m", "grpc_tools.protoc", "-I.", "--python_out=.", "--pyi_out=.", *proto_files]
    try:
        subprocess.run(cmd, check=True)
    except (FileNotFoundError, subprocess.CalledProcessError) as err:
        raise LibError("Error while generating protobuf modules: " + str(err)) from err


def clean_unicornlib():
    oglob = glob.glob("native/*.o")
    oglob += glob.glob("native/*.obj")
    oglob += glob.glob("native/*.so")
    oglob += glob.glob("native/*.dll")
    oglob += glob.glob("native/*.dylib")
    for fname in oglob:
        os.unlink(fname)


class build_rust(setuptools_rust.build_rust):
    def run(self):
        configure_z3()
        super().run()


class build(st_build):
    def run(self, *args):
        self.execute(build_protos, (), msg="Generating protobuf modules")
        if not is_wasm_build:
            self.execute(build_unicornlib, (), msg="Building unicornlib")
        super().run(*args)


class clean(Command):
    user_options = []

    def initialize_options(self):
        pass

    def finalize_options(self):
        pass

    def run(self):
        self.execute(clean, (), msg="Cleaning unicornlib")


class develop(st_develop):
    def run(self):
        self.run_command("build")
        super().run()


cmdclass = {
    "build": build,
    "build_rust": build_rust,
    "clean_unicornlib": clean,
    "develop": develop,
}


try:
    from setuptools.command.editable_wheel import editable_wheel as st_editable_wheel

    class editable_wheel(st_editable_wheel):
        def run(self):
            self.run_command("build")
            super().run()

    cmdclass["editable_wheel"] = editable_wheel
except ModuleNotFoundError:
    pass


setup(cmdclass=cmdclass)
