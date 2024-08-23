#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.reaching_definitions"  # pylint:disable=redefined-builtin

from typing import TYPE_CHECKING
import os
from unittest import main, TestCase

import claripy

import angr
from angr.analyses.reaching_definitions import FunctionHandler
from angr.storage.memory_mixins.paged_memory.pages.multi_values import MultiValues
from angr.errors import SimMemoryMissingError

if TYPE_CHECKING:
    from angr.analyses.reaching_definitions.rd_state import ReachingDefinitionsState
    from angr.analyses.reaching_definitions import FunctionCallData

from ...common import bin_location


TESTS_LOCATION = os.path.join(bin_location, "tests")


def load_cstring_from_loader_memory(project, addr: int, as_str: bool = False):
    # This function loads a null-terminated string from the static memory region
    s = b""
    while True:
        char_addr = addr + len(s)
        try:
            v = project.loader.memory.load(char_addr, 1)
        except KeyError:
            break
        if v == b"\x00":
            break
        s += v
    return s.decode("utf-8") if as_str else (s + b"\x00")


def load_cstring_from_memory_definitions(ld, addr: int, as_str: bool = False):
    # This function loads a null-terminated string from the memory definitions
    s = b""
    while True:
        char_addr = addr + len(s)
        try:
            v = ld.memory.load(char_addr, 1).one_value().concrete_value
        except SimMemoryMissingError:
            break
        if v == 0:
            break
        s += v.to_bytes(1, "little")
    return s.decode("utf-8") if as_str else (s + b"\x00")


class CustomFunctionHandler(FunctionHandler):
    def __init__(self, project):
        self.project = project
        self.system_cmd = ""
        self.strcpy_addr = None
        self.sscanf_str_addr = None
        self.sscanf_str = None
        self.sscanf_fmtstr_addr = None
        self.sscanf_fmtstr = None
        self.sscanf_out_value = None
        self.malloc_sizes = []

    def handle_impl_malloc(self, state: ReachingDefinitionsState, data: FunctionCallData):
        ((src_atom,),) = data.args_atoms

        src_value = state.get_values(src_atom).one_value().concrete_value
        self.malloc_sizes.append(src_value)
        data.depends(next(iter(data.ret_atoms)), value=MultiValues(claripy.BVV(0x12345678, 64)))

    def handle_impl___isoc99_sscanf(self, state: ReachingDefinitionsState, data: FunctionCallData):
        (str_atom,), (fmtstr_atom,), (out_atom,) = data.args_atoms[:3]

        # string
        str_addr = state.get_values(str_atom).one_value().concrete_value
        self.sscanf_str_addr = str_addr
        str_ = load_cstring_from_loader_memory(self.project, str_addr)
        self.sscanf_str = str_

        # format string: "%d"
        fmtstr_addr = state.get_values(fmtstr_atom).one_value().concrete_value
        self.sscanf_fmtstr_addr = fmtstr_addr
        fmtstr = load_cstring_from_loader_memory(self.project, str_addr)
        self.sscanf_fmtstr = fmtstr

        # out pointer
        (dst,) = state.pointer_to_atoms(state.get_values(out_atom), size=4, endness=state.arch.memory_endness)
        (src,) = state.pointer_to_atoms(state.get_values(str_atom), size=len(str_), endness="Iend_BE")
        self.sscanf_out_value = int(str_.strip(b"\x00"))
        data.depends(dst, src, value=MultiValues(claripy.BVV(self.sscanf_out_value, 32)))

    def handle_impl_strcpy(self, state: ReachingDefinitionsState, data: FunctionCallData):
        (dst_atom,), (src_atom,) = data.args_atoms

        # Assume source is a constant string
        src_addr = state.get_values(src_atom).one_value().concrete_value
        self.strcpy_addr = src_addr
        src_str = load_cstring_from_loader_memory(self.project, src_addr)
        src_str_size = len(src_str)

        (dst,) = state.pointer_to_atoms(state.get_values(dst_atom), size=src_str_size, endness="Iend_BE")
        (src,) = state.pointer_to_atoms(state.get_values(src_atom), size=src_str_size, endness="Iend_BE")

        data.depends(dst, src, value=MultiValues(claripy.BVV(src_str)))

    def handle_impl_system(self, state: ReachingDefinitionsState, data: FunctionCallData):
        (cmd_atom,) = data.args_atoms[0]
        cmd_addr = state.get_values(cmd_atom).one_value().concrete_value
        self.system_cmd = load_cstring_from_memory_definitions(state.live_definitions, cmd_addr, as_str=True)


class TestFunctionhandler(TestCase):
    def test_function_handler_depends_has_endness(self):
        filename = os.path.join(TESTS_LOCATION, "x86_64", "rda_function_handler")
        project = angr.Project(filename, auto_load_libs=False)
        _ = project.analyses.CFGFast()
        handler = CustomFunctionHandler(project)
        _ = project.analyses.ReachingDefinitions("main", function_handler=handler)

        assert handler.system_cmd == "ABCDEFGH"
        assert handler.sscanf_str == b"12345678\x00"
        assert handler.sscanf_out_value == 12345678
        assert handler.malloc_sizes == [20, 12345678]


if __name__ == "__main__":
    main()
