# pylint:disable=no-self-use
from __future__ import annotations
import os
import subprocess
import tempfile
import unittest

import archinfo

import angr


def nasm(asm: str) -> bytes:
    """
    Use NASM to assemble `asm` and return the machine code.
    """
    with tempfile.NamedTemporaryFile(suffix=".nasm", delete=False) as f_in:
        path_out = f_in.name + ".bin"
        try:
            f_in.write(asm.encode("utf-8"))
            f_in.close()

            subprocess.check_call(["nasm", "-fbin", "-o" + path_out, f_in.name])
            with open(path_out, "rb") as f_out:
                data = f_out.read()
            os.unlink(path_out)
        finally:
            os.unlink(f_in.name)
    return data


def gcc(c: str) -> str:
    """
    Use GCC compile `c` and return path to the binary.
    """
    with tempfile.NamedTemporaryFile(suffix=".c", delete=False) as f_in:
        path_out = f_in.name + ".bin"
        try:
            f_in.write(c.encode("utf-8"))
            f_in.close()

            subprocess.check_call(["gcc", "-o", path_out, f_in.name])
            return path_out
        finally:
            os.unlink(f_in.name)


class TestTraceClassifier(unittest.TestCase):
    """
    TraceClassifier tests
    """

    def test_not_smc_shellcode(self):
        """
        Simple not-self-modifying shellcode.
        """
        code_bytes = nasm(
            """
			bits 64
			default rel
			mov rax, 0xdeadbeef
			ret
			"""
        )
        p = angr.load_shellcode(code_bytes, "amd64", selfmodifying_code=True)
        is_smc = p.analyses.SMC(p.entry).result
        assert not is_smc

    def test_smc_shellcode(self):
        """
        Simple self-modifying shellcode.
        """
        code_bytes = nasm(
            """
			bits 64
			default rel
			inc dword [here+1]
			here:
			mov rax, 0xdeadbeef
			ret
			"""
        )
        p = angr.load_shellcode(code_bytes, "amd64", selfmodifying_code=True)
        is_smc = p.analyses.SMC(p.entry).result
        assert is_smc

    def test_smc_buffer(self):
        """
        Evaluate a binary that allocates a buffer, writes code to that buffer, then runs it.
        """
        arch = archinfo.ArchAMD64()
        code_asm = "mov eax, 0xdeadbeef; ret"
        code_bytes, _ = arch.keystone.asm(code_asm, as_bytes=True)
        code_as_hex = "".join(f"\\x{b:02x}" for b in code_bytes)
        code_len = len(code_bytes)
        c_src = f"""
		#include <assert.h>
		#include <stdlib.h>
		#include <malloc.h>
		#include <stdio.h>
		#include <string.h>
		#include <sys/mman.h>
		#include <unistd.h>
		#define ALIGN_UP(v, align) (((v)+(align)-1)&~((align)-1))
		int main(int argc, char **argv) {{
			size_t page_size = sysconf(_SC_PAGE_SIZE);
			assert(page_size != -1);
			size_t buf_size = ALIGN_UP({code_len}, page_size);
			// we can't symbolically execute through memalign in native glibc yet
			// void *buf = memalign(page_size, buf_size);
			void *buf = malloc(buf_size);
			assert(buf);
			memcpy(buf, \"{code_as_hex}\", {code_len});
			int status = mprotect(buf, buf_size, PROT_EXEC | PROT_READ);
			assert(status != -1);
			int v = ( (int(*)(void)) buf )();
			printf("v = 0x%x\\n", v);
			return 0;
		}}
		"""

        path = gcc(c_src)
        p = angr.Project(path, selfmodifying_code=True, auto_load_libs=False)
        is_smc = p.analyses.SMC("main").result
        assert is_smc


def main():
     unittest.main()


if __name__ == "__main__":
    main()
