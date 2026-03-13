import logging

import angr

angr_rust_logger = logging.getLogger("angr.rust")
angr_rust_logger.setLevel(logging.DEBUG)

BINARY_NAME = "binaries/FakeCrypt-stripped"
TARGET_ADDR = 0x455300

if __name__ == "__main__":
    proj = angr.Project(BINARY_NAME, auto_load_libs=False, is_rust_binary=True)
    print("[*] Running CFGFast ...")
    proj.analyses.CFGFast(normalize=True)
    print("[*] Running CompleteCallingConventions ...")
    proj.analyses.CompleteCallingConventions(recover_variables=False)
    print("[*] Running RustSymbolRecovery ...")
    proj.analyses.RustSymbolRecovery()
    print("[*] Running TypeDBLoader ...")
    proj.analyses.TypeDBLoader()

    func = proj.kb.functions.get_by_addr(TARGET_ADDR)
    print("[*] Running Decompiler ...")
    decompiler = proj.analyses.Decompiler(func)
    print("[*] Decompiled code:")
    print(decompiler.codegen.text)
