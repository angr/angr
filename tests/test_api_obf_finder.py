from unittest import TestCase, main

import os

import angr
from angr.analyses import deobfuscator

binaries_base = os.path.join(
    os.path.dirname(os.path.realpath(str(__file__))),
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

        proj.analyses.CompleteCallingConventions(recover_variables=True, workers=4)

        # it will update kb.obfuscations
        finder = proj.analyses.APIObfuscationFinder()
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
        print(dec.codegen.text)


if __name__ == "__main__":
    # main()
    TestAPIObfFinder().test_smoketest()
