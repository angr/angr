from __future__ import annotations

from types import SimpleNamespace

import archinfo

from angr.analyses.decompiler.structured_codegen.base import BaseStructuredCodeGenerator
from angr.analyses.decompiler.structured_codegen.c import CConstant
from angr.knowledge_plugins.cfg.memory_data import MemoryData, MemoryDataSort
from angr.sim_type import SimTypeChar, SimTypePointer, SimTypeWideChar


class _Loader:
    def find_section_containing(self, addr):
        return SimpleNamespace(is_writable=addr == 0x402000)

    @staticmethod
    def find_segment_containing(addr):
        return SimpleNamespace(is_writable=addr == 0x402000)


def _render_memory_data_constant(addr: int, content: bytes, *, wide: bool = False) -> str:
    arch = archinfo.ArchAMD64()
    codegen = BaseStructuredCodeGenerator()
    codegen.project = SimpleNamespace(arch=arch, loader=_Loader())
    codegen.max_str_len = None

    pointee = SimTypeWideChar() if wide else SimTypeChar()
    pointer_type = SimTypePointer(pointee).with_arch(arch)
    memory_data = MemoryData(
        addr,
        len(content),
        MemoryDataSort.UnicodeString if wide else MemoryDataSort.String,
    )
    memory_data.content = content
    constant = CConstant(
        addr,
        pointer_type,
        reference_values={pointer_type: memory_data},
        codegen=codegen,
    )
    return "".join(text for text, _ in constant.c_repr_chunks())


def test_readonly_string_memory_data_is_rendered_as_literal():
    assert _render_memory_data_constant(0x401000, b"hello") == '"hello"'
    assert _render_memory_data_constant(0x401000, "hello".encode("utf-16-le"), wide=True) == 'L"hello"'


def test_writable_string_memory_data_preserves_address():
    assert _render_memory_data_constant(0x402000, b"hello") == "(char *)0x402000"
    assert _render_memory_data_constant(0x402000, "hello".encode("utf-16-le"), wide=True) == "(wchar *)0x402000"
