#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,line-too-long,protected-access
from __future__ import annotations

__package__ = __package__ or "tests.knowledge_plugins.functions"  # pylint:disable=redefined-builtin

import os
import unittest

import angr
import angr.calling_conventions
from angr.knowledge_plugins.functions.function import _is_posix_library_name
from angr.procedures.definitions import SimSyscallLibrary
from angr.sim_type import SimTypePointer
from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")

# A 32-bit Windows PE whose Winsock imports name wsock32.dll, which angr has no definitions for, so
# CallingConventionAnalysis falls back to searching every library for the declaration.
PE_WITH_WINSOCK_IMPORTS = "064e1d62c8542d658d83f7e231cc3b935a1f18153b8aea809dcccfd446a91c93"


class TestPrototypes(unittest.TestCase):
    def test_function_prototype(self):
        proj = angr.Project(os.path.join(test_location, "x86_64", "all"), auto_load_libs=False)

        func = angr.knowledge_plugins.Function(proj.kb.functions, 0x100000, name="strcmp")
        func.prototype = angr.SIM_LIBRARIES["libc.so.6"][0].prototypes[func.name]
        func.calling_convention = angr.calling_conventions.default_cc(proj.arch.name, platform="Linux")(proj.arch)

    def test_find_prototype(self):
        proj = angr.Project(os.path.join(test_location, "x86_64", "all"), auto_load_libs=False)

        cfg = proj.analyses.CFG()

        func = cfg.kb.functions.function(name="strcmp", plt=False)
        func.calling_convention = angr.calling_conventions.default_cc(proj.arch.name, platform="Linux")(proj.arch)

        func.find_declaration()

        arg_locs = func.calling_convention.arg_locs(func.prototype)

        assert len(arg_locs) == 2
        assert arg_locs[0].reg_name == "rdi"
        assert arg_locs[1].reg_name == "rsi"

    def test_declaration_search_prefers_the_image_platform(self):
        # ws2_32.dll and libc both declare socket(), with incompatible prototypes, so which library
        # find_declaration reaches first decides what a Windows PE's imports look like. Loading the PE first
        # registers the Win32 definitions, which is what puts the two declarations in competition.
        pe_proj = angr.Project(
            os.path.join(test_location, "i386", "windows", PE_WITH_WINSOCK_IMPORTS), auto_load_libs=False
        )
        pe_func = angr.knowledge_plugins.Function(pe_proj.kb.functions, 0x100000, name="socket")
        assert pe_func.find_declaration(ignore_binary_name=True)
        assert pe_func.prototype_libname == "ws2_32.dll"

        elf_proj = angr.Project(os.path.join(test_location, "x86_64", "all"), auto_load_libs=False)
        elf_func = angr.knowledge_plugins.Function(elf_proj.kb.functions, 0x100000, name="socket")
        assert elf_func.find_declaration(ignore_binary_name=True)
        assert elf_func.prototype_libname == "libc.so.0"

    def test_declaration_libraries_are_deduplicated_and_grouped_by_platform(self):
        pe_proj = angr.Project(
            os.path.join(test_location, "i386", "windows", PE_WITH_WINSOCK_IMPORTS), auto_load_libs=False
        )
        func = angr.knowledge_plugins.Function(pe_proj.kb.functions, 0x100000, name="socket")
        candidates = [
            library
            for libraries in angr.SIM_LIBRARIES.values()
            for library in libraries
            if not isinstance(library, SimSyscallLibrary)
        ]
        ranked = func._rank_declaration_libraries(candidates)

        # a library is registered under each of its names, so the candidate list repeats
        assert len(candidates) > len(ranked)
        assert len(ranked) == len({id(library) for library in candidates})

        posix = [index for index, library in enumerate(ranked) if _is_posix_library_name(library.name)]
        assert posix, "nothing to order: no POSIX library is registered"
        # for a PE the POSIX declarations come last, and each group is sorted by name
        assert posix == list(range(len(ranked) - len(posix), len(ranked)))
        assert [library.name for library in ranked[: posix[0]]] == sorted(
            library.name for library in ranked[: posix[0]]
        )
        assert [library.name for library in ranked[posix[0] :]] == sorted(
            library.name for library in ranked[posix[0] :]
        )

    def test_cpp_void_pointer(self):
        proj = angr.Project(os.path.join(test_location, "x86_64", "void_pointer"), auto_load_libs=False)

        cfg = proj.analyses.CFG()
        proj.analyses.CompleteCallingConventions(recover_variables=True, analyze_callsites=True)

        func = cfg.kb.functions.function(name="_ZdlPvm", plt=True)
        assert isinstance(func.prototype.args[0], SimTypePointer)


if __name__ == "__main__":
    unittest.main()
