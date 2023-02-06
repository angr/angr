import sys
import platform
import os
import tempfile
import subprocess
import shutil

from common import has_32_bit_compiler_support

import angr


test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "binaries", "tests")

# Note: Reassembler is intensively tested by Patcherex test cases on CGC binaries.


def is_linux_x64():
    return sys.platform.startswith("linux") and platform.machine().endswith("64")


def is_linux():
    return sys.platform.startswith("linux")


def test_data_reference_collection_in_add():
    # Issue reported and test binary provided by Antonio F. Montoya
    # Fixed in https://github.com/angr/pyvex/pull/192

    p = angr.Project(os.path.join(test_location, "x86_64", "df_gcc_-O1"), auto_load_libs=False)
    vexblock_opt0 = p.factory.block(0x402431, opt_level=0).vex
    vexblock_opt1 = p.factory.block(0x402431, opt_level=1).vex
    vexblock_opt1_nostmt = p.factory.block(0x402431, opt_level=1, collect_data_refs=True).vex_nostmt

    cfg = p.analyses.CFG()

    cfg._model.memory_data = {}
    cfg._collect_data_references(vexblock_opt0, 0x402431)
    memory_data_opt0 = cfg._model.memory_data

    cfg._model.memory_data = {}
    # bypass the IRSB unoptimization step
    cfg._collect_data_references_by_scanning_stmts(vexblock_opt1, 0x402431)
    memory_data_opt1 = cfg._model.memory_data

    cfg._model.memory_data = {}
    cfg._collect_data_references(vexblock_opt1_nostmt, 0x402431)
    memory_data_opt1_nostmt = cfg._model.memory_data

    assert memory_data_opt0.keys() == memory_data_opt1.keys()
    assert memory_data_opt0.keys() == memory_data_opt1_nostmt.keys()


def test_ln_gcc_O2():
    # Issue reported and test binary provided by Antonio F. Montoya

    p = angr.Project(os.path.join(test_location, "x86_64", "ln_gcc_-O2"), auto_load_libs=False)
    r = p.analyses.Reassembler(syntax="at&t")
    r.symbolize()
    r.remove_unnecessary_stuff()
    assembly = r.assembly(comments=True, symbolized=True)

    # There should be two symbols with the same name: file_name. Reassembler renames the second one to file_name_0.
    # Test their existence.
    assert "\nfile_name:" in assembly and "\nfile_name_0:" in assembly

    if is_linux_x64():
        # we should be able to compile it and run it ... if we are running on x64 Linux
        tempdir = tempfile.mkdtemp(prefix="angr_test_reassembler_")
        asm_filename = "ln_gcc-O2.s"
        bin_filename = "ln_gcc-O2"
        asm_filepath = os.path.join(tempdir, asm_filename)
        bin_filepath = os.path.join(tempdir, bin_filename)
        with open(asm_filepath, "w", encoding="ascii") as f:
            f.write(assembly)
        # Call out to GCC, and it should return 0. Otherwise check_call() will raise an exception.
        subprocess.check_call(
            ["gcc", "-no-pie", asm_filepath, "-o", bin_filepath], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        # Run the generated binary file, and it should not crash (which is a pretty basic requirement, I know)
        subprocess.check_call([bin_filepath, "--help"], stdout=subprocess.DEVNULL)
        # Pick up after ourselves
        shutil.rmtree(tempdir)


def test_chmod_gcc_O1():
    # Issue reported and test binary provided by Antonio F. Montoya

    p = angr.Project(os.path.join(test_location, "x86_64", "chmod_gcc_-O1"), auto_load_libs=False)
    r = p.analyses.Reassembler(syntax="at&t")
    r.symbolize()
    r.remove_unnecessary_stuff()
    assembly = r.assembly(comments=True, symbolized=True)

    if is_linux_x64():
        # we should be able to compile it and run it ... if we are running on x64 Linux
        tempdir = tempfile.mkdtemp(prefix="angr_test_reassembler_")
        asm_filename = "chmod_gcc-O1.s"
        bin_filename = "chmod_gcc-O1"
        asm_filepath = os.path.join(tempdir, asm_filename)
        bin_filepath = os.path.join(tempdir, bin_filename)
        with open(asm_filepath, "w", encoding="ascii") as f:
            f.write(assembly)
        # Call out to GCC, and it should return 0. Otherwise check_call() will raise an exception.
        subprocess.check_call(
            ["gcc", "-no-pie", asm_filepath, "-o", bin_filepath], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        # Run the generated binary file, and it should not crash (which is a pretty basic requirement, I know)
        subprocess.check_call([bin_filepath, "--help"], stdout=subprocess.DEVNULL)
        # Pick up after ourselves
        shutil.rmtree(tempdir)


def test_ex_gpp():
    # Issue reported and test binary provided by Antonio F. Montoya

    p = angr.Project(os.path.join(test_location, "x86_64", "ex_g++"), auto_load_libs=False)
    r = p.analyses.Reassembler(syntax="at&t")
    r.symbolize()
    r.remove_unnecessary_stuff()
    assembly = r.assembly(comments=True, symbolized=True)

    if is_linux_x64():
        # we should be able to compile it and run it ... if we are running on x64 Linux
        tempdir = tempfile.mkdtemp(prefix="angr_test_reassembler_")
        asm_filename = "ex_g++.s"
        bin_filename = "ex_g++"
        asm_filepath = os.path.join(tempdir, asm_filename)
        bin_filepath = os.path.join(tempdir, bin_filename)
        with open(asm_filepath, "w", encoding="ascii") as f:
            f.write(assembly)
        # Call out to GCC, and it should return 0. Otherwise check_call() will raise an exception.
        subprocess.check_call(
            ["g++", "-no-pie", asm_filepath, "-o", bin_filepath], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        # Run the generated binary file and check the output
        output = subprocess.check_output([bin_filepath])
        assert output == b"A1\nA2\n"
        # Pick up after ourselves
        shutil.rmtree(tempdir)


def test_df_gcc_O1():
    # Issue reported and test binary provided by Antonio F. Montoya

    p = angr.Project(os.path.join(test_location, "x86_64", "df_gcc_-O1"), auto_load_libs=False)
    r = p.analyses.Reassembler(syntax="at&t")
    r.symbolize()
    r.remove_unnecessary_stuff()
    assembly = r.assembly(comments=True, symbolized=True)

    if is_linux_x64():
        # we should be able to compile it and run it ... if we are running on x64 Linux
        tempdir = tempfile.mkdtemp(prefix="angr_test_reassembler_")
        asm_filename = "df_gcc-O1.s"
        bin_filename = "df_gcc-O1"
        asm_filepath = os.path.join(tempdir, asm_filename)
        bin_filepath = os.path.join(tempdir, bin_filename)
        with open(asm_filepath, "w", encoding="ascii") as f:
            f.write(assembly)
        # Call out to GCC, and it should return 0. Otherwise check_call() will raise an exception.
        subprocess.check_call(
            ["gcc", "-no-pie", asm_filepath, "-o", bin_filepath], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        # Run the generated binary file, and it should not crash (which is a pretty basic requirement, I know)
        subprocess.check_call([bin_filepath, "--help"], stdout=subprocess.DEVNULL)
        # Pick up after ourselves
        shutil.rmtree(tempdir)


def test_dir_gcc_O0():
    # Issue reported and test binary provided by Antonio F. Montoya

    p = angr.Project(os.path.join(test_location, "x86_64", "dir_gcc_-O0"), auto_load_libs=False)
    r = p.analyses.Reassembler(syntax="at&t")
    r.symbolize()
    r.remove_unnecessary_stuff()
    assembly = r.assembly(comments=True, symbolized=True)

    if is_linux_x64():
        # we should be able to compile it and run it ... if we are running on x64 Linux
        tempdir = tempfile.mkdtemp(prefix="angr_test_reassembler_")
        asm_filename = "dir_gcc-O0.s"
        bin_filename = "dir_gcc-O0"
        asm_filepath = os.path.join(tempdir, asm_filename)
        bin_filepath = os.path.join(tempdir, bin_filename)
        with open(asm_filepath, "w", encoding="ascii") as f:
            f.write(assembly)
        # Call out to GCC, and it should return 0. Otherwise check_call() will raise an exception.
        subprocess.check_call(
            ["gcc", "-no-pie", asm_filepath, "-o", bin_filepath], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        # Run the generated binary file, and it should not crash (which is a pretty basic requirement, I know)
        subprocess.check_call([bin_filepath, "--help"], stdout=subprocess.DEVNULL)
        subprocess.check_call([bin_filepath, "-la", "/"], stdout=subprocess.DEVNULL)
        # Pick up after ourselves
        shutil.rmtree(tempdir)


def test_helloworld():
    # Reassembler complains about TYPE_OTHER symbols, which is because it's trying to classify bytes inside the ELF
    # header as pointers. We identify the ELF header in CFGFast to workaround this problem.
    # https://github.com/angr/angr/issues/1630

    p = angr.Project(os.path.join(test_location, "x86_64", "hello_world"), auto_load_libs=False)
    r = p.analyses.Reassembler(syntax="at&t")
    r.symbolize()
    r.remove_unnecessary_stuff()
    _ = r.assembly(comments=True, symbolized=True)

    # No exception should have been raised


def test_helloworld_gcc9():
    # New versions of GCC changed the names of init and fini sections.
    # https://github.com/angr/patcherex/issues/39

    p = angr.Project(os.path.join(test_location, "x86_64", "hello_gcc9_reassembler"), auto_load_libs=False)
    r = p.analyses.Reassembler(syntax="at&t")
    r.symbolize()
    r.remove_unnecessary_stuff()
    assembly = r.assembly(comments=True, symbolized=True)

    if is_linux_x64():
        # we should be able to compile it and run it ... if we are running on x64 Linux
        tempdir = tempfile.mkdtemp(prefix="angr_test_reassembler_")
        asm_filename = "hello.s"
        bin_filename = "hello"
        asm_filepath = os.path.join(tempdir, asm_filename)
        bin_filepath = os.path.join(tempdir, bin_filename)
        with open(asm_filepath, "w", encoding="ascii") as f:
            f.write(assembly)
        # Call out to GCC, and it should return 0. Otherwise check_call() will raise an exception.
        subprocess.check_call(
            ["gcc", "-no-pie", asm_filepath, "-o", bin_filepath], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        # Run the generated binary file, and it should not crash
        subprocess.check_call([bin_filepath], stdout=subprocess.DEVNULL)
        # Pick up after ourselves
        shutil.rmtree(tempdir)


def test_partial_pie_ls_x86():
    # https://github.com/angr/patcherex/issues/39
    # a GCC-generated X86 binary with a few functions somehow being PIE

    p = angr.Project(os.path.join(test_location, "i386", "ls_gcc_7.5_reassembler"), auto_load_libs=False)
    r = p.analyses.Reassembler(syntax="at&t")
    r.symbolize()
    r.remove_unnecessary_stuff()
    assembly = r.assembly(comments=True, symbolized=True)

    if is_linux() and has_32_bit_compiler_support():
        # we should be able to compile it and run it ... if we are running on x64 Linux
        tempdir = tempfile.mkdtemp(prefix="angr_test_reassembler_")
        asm_filename = "ls.s"
        bin_filename = "ls"
        asm_filepath = os.path.join(tempdir, asm_filename)
        bin_filepath = os.path.join(tempdir, bin_filename)
        with open(asm_filepath, "w", encoding="ascii") as f:
            f.write(assembly)
        # Call out to GCC, and it should return 0. Otherwise check_call() will raise an exception.
        subprocess.check_call(
            ["gcc", "-m32", "-no-pie", asm_filepath, "-o", bin_filepath],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        # Run the generated binary file, and it should not crash
        subprocess.check_call([bin_filepath], stdout=subprocess.DEVNULL)
        # We can also run it with "-h"
        o = subprocess.check_output([bin_filepath, "--version"])
        assert (
            o == b"ls (GNU coreutils) 8.30\n"
            b"Copyright (C) 2018 Free Software Foundation, Inc.\n"
            b"License GPLv3+: GNU GPL version 3 or later <https://gnu.org/licenses/gpl.html>.\n"
            b"This is free software: you are free to change and redistribute it.\n"
            b"There is NO WARRANTY, to the extent permitted by law.\n\n"
            b"Written by Richard M. Stallman and David MacKenzie.\n"
        )
        # Pick up after ourselves
        shutil.rmtree(tempdir)


if __name__ == "__main__":
    test_data_reference_collection_in_add()
    test_ln_gcc_O2()
    test_chmod_gcc_O1()
    test_ex_gpp()
    test_df_gcc_O1()
    test_dir_gcc_O0()
    test_helloworld()
    test_helloworld_gcc9()
    test_partial_pie_ls_x86()
