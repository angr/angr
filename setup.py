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
from pathlib import Path

import setuptools_rust
from setuptools import Command, setup
from setuptools.command.build import build as st_build
from setuptools.command.develop import develop as st_develop
from setuptools.errors import LibError

if sys.platform == "darwin":
    library_file = "unicornlib.dylib"
elif sys.platform in ("win32", "cygwin"):
    library_file = "unicornlib.dll"
else:
    library_file = "unicornlib.so"


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
        # importlib.resources.files() returns a MultiplexedPath for editable
        # installs, whose str() is not a filesystem path; resolve via the
        # imported package's location instead.
        pkg_file = importlib.import_module(pkg).__file__
        if pkg_file is None:
            raise LibError(f"Cannot locate {pkg} on disk; is it installed as a namespace package?")
        env[var] = os.path.join(os.path.dirname(pkg_file), *fnm.split("\\"))

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


def build_z3_import_library(library_dir: Path) -> Path:
    """Generate libz3.lib for the libz3.dll in the z3-solver wheel, and return the directory holding it.

    MSVC's linker cannot take a DLL as input; it wants an import library, a table of export names
    mapped to the DLL's name. The wheel ships none, but the table is read straight out of the DLL.
    """
    import pefile

    dll = pefile.PE(library_dir / "libz3.dll", fast_load=True)
    dll.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]])
    exports = [symbol.name.decode() for symbol in dll.DIRECTORY_ENTRY_EXPORT.symbols if symbol.name]
    machine = pefile.MACHINE_TYPE[dll.FILE_HEADER.Machine].removeprefix("IMAGE_FILE_MACHINE_")

    out_dir = Path(__file__).resolve().parent / "build" / "z3"
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "libz3.def").write_text("LIBRARY libz3.dll\nEXPORTS\n" + "".join(f"    {name}\n" for name in exports))
    rustc = subprocess.run(
        ["rustc", "--print", "sysroot", "--print", "host-tuple"], check=True, capture_output=True, text=True
    )
    sysroot, host = rustc.stdout.split()
    rust_lld = Path(sysroot) / "lib" / "rustlib" / host / "bin" / "rust-lld.exe"
    cmd = [
        rust_lld,
        "-flavor",
        "link",
        f"/DEF:{out_dir / 'libz3.def'}",
        f"/MACHINE:{machine}",
        f"/OUT:{out_dir / 'libz3.lib'}",
    ]
    subprocess.run(cmd, check=True)
    return out_dir


def configure_z3():
    """Point the Rust build at the libz3 that ships in the z3-solver wheel.

    z3-sys probes pkg-config before honoring the override, and its search path would win, so a
    machine with a system-wide Z3 of another version would link that instead -- the bindings are
    tied to one Z3 release. On Windows the override has to name an import library, which the wheel
    does not ship, so one is generated from the wheel's DLL first. angr/_z3.py loads the wheel's
    libz3 at runtime everywhere.
    """
    try:
        library_dir = z3_loader().library_dir()
    except ImportError as err:
        raise LibError("You must install z3-solver before building angr") from err

    if sys.platform == "win32":
        library_dir = build_z3_import_library(library_dir)
    os.environ.setdefault("Z3_NO_PKG_CONFIG", "1")
    os.environ.setdefault("Z3_LIBRARY_PATH_OVERRIDE", str(library_dir))


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
