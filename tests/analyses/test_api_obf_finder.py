# pylint:disable=missing-class-docstring,no-self-use,protected-access

from __future__ import annotations

import os
from unittest import TestCase, main

import angr
from angr.analyses.decompiler.decompilation_options import PARAM_TO_OPTION

binaries_base = os.path.join(
    os.path.dirname(os.path.realpath(str(__file__))),
    "..",
    "..",
    "..",
    "binaries",
    "tests",
)


class TestAPIObfFinder(TestCase):
    def test_smoketest(self):
        bin_path = os.path.join(
            binaries_base, "x86_64", "windows", "fc7a8e64d88ad1d8c7446c606731901063706fd2fb6f9e237dda4cb4c966665b"
        )

        proj = angr.Project(bin_path, auto_load_libs=False)
        cfg = proj.analyses.CFG(normalize=True)

        proj.analyses.CompleteCallingConventions()

        # it will update kb.obfuscations
        finder = proj.analyses.APIObfuscationFinder(fail_fast=True)
        assert finder.type1_candidates
        assert proj.kb.obfuscations.type1_deobfuscated_apis == {
            0x40A030: ("Advapi32.dll", "AllocateAndInitializeSid"),
            0x40A038: ("Advapi32.dll", "CheckTokenMembership"),
            0x40A040: ("Advapi32.dll", "FreeSid"),
            0x40A048: ("Shell32.dll", "ShellExecuteExA"),
            0x40A050: ("Kernel32.dll", "TerminateProcess"),
            0x40A058: ("Kernel32.dll", "GetModuleFileNameA"),
            0x40A060: ("Kernel32.dll", "CreateFileA"),
            0x40A068: ("Kernel32.dll", "DeviceIoControl"),
            0x40A070: ("Kernel32.dll", "CloseHandle"),
            0x40A078: ("Kernel32.dll", "CreateToolhelp32Snapshot"),
            0x40A080: ("Kernel32.dll", "Process32First"),
            0x40A088: ("Kernel32.dll", "Process32Next"),
            0x40A090: ("User32.dll", "ShowWindow"),
            0x40A098: ("Kernel32.dll", "GetEnvironmentVariableA"),
            0x40A0A0: ("User32.dll", "MessageBoxA"),
        }

        dec = proj.analyses.Decompiler(cfg.kb.functions[0x401530], cfg=cfg.model)
        assert dec.codegen is not None, "Decompilation failed"
        print(dec.codegen.text)

    def test_type2(self):
        bin_path = os.path.join(binaries_base, "x86_64", "windows", "GetProcAddress.exe")
        func_ptr_addr, func_name = 0x140007030, "MessageBoxA"

        proj = angr.Project(bin_path, auto_load_libs=False)
        proj.analyses.CFG(normalize=True)
        proj.analyses.CompleteCallingConventions()

        # Ensure variable not resolved yet (via symbols)
        assert not proj.kb.variables["global"].get_global_variables(func_ptr_addr)

        proj.analyses.APIObfuscationFinder()

        # Ensure APIObfuscationFinder resolved the call to GetProcAddress
        assert proj.kb.obfuscations.type2_deobfuscated_apis == {func_ptr_addr: func_name}
        (var,) = proj.kb.variables["global"].get_global_variables(func_ptr_addr)
        assert var.name == f"p_{func_name}"

    def test_undecompilable_functions_are_skipped(self):
        # issue #7134: the hash-lookup lifter asserted on Decompiler.clinic being None
        bin_path = os.path.join(binaries_base, "x86_64", "windows", "GetProcAddress.exe")

        proj = angr.Project(bin_path, auto_load_libs=False)
        proj.analyses.CFG(normalize=True)
        proj.analyses.CompleteCallingConventions()

        # make every decompilation abort on the complexity limit, so no function yields a clinic
        options = [(PARAM_TO_OPTION["max_function_blocks"], 1)]
        assert proj.analyses.Decompiler(proj.kb.functions[proj.entry], options=options, fail_fast=False).clinic is None
        finder = proj.analyses.APIObfuscationFinder(decompiler_options=options, fail_fast=False)

        assert (
            finder._hash_lookup_api_deobfuscator_lifter(proj.kb.functions["GetProcAddress"], decompiler_options=options)
            is None
        )
        assert not proj.kb.obfuscations.type3_deobfuscated_apis


if __name__ == "__main__":
    main()
