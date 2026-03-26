import argparse
import logging

import angr

angr_rust_logger = logging.getLogger("angr.rust")
angr_rust_logger.setLevel(logging.DEBUG)

TARGET_ADDR = 0x455300

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--unstripped", action="store_true", help="Use unstripped FakeCrypt binary and skip RustSymbolRecovery")
    args = parser.parse_args()

    binary = "binaries/FakeCrypt" if args.unstripped else "binaries/FakeCrypt-stripped"
    proj = angr.Project(binary, auto_load_libs=False, is_rust_binary=True)
    print("[*] Running CFGFast ...")
    proj.analyses.CFGFast(normalize=True, show_progressbar=True)
    print("[*] Running CompleteCallingConventions ...")
    proj.analyses.CompleteCallingConventions(recover_variables=False, show_progressbar=True)
    if not args.unstripped:
        print("[*] Running RustSymbolRecovery ...")
        proj.analyses.RustSymbolRecovery()
    print("[*] Running TypeDBLoader ...")
    proj.analyses.TypeDBLoader()

    func = proj.kb.functions.get_by_addr(TARGET_ADDR)
    print("[*] Running Decompiler ...")
    decompiler = proj.analyses.Decompiler(func, fail_fast=True)
    print("[*] Decompiled code:")
    print(decompiler.codegen.text)
