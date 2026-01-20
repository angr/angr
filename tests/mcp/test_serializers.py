from __future__ import annotations

import pytest

from angr.mcp.serializers import (
    serialize_function,
    serialize_function_summary,
    serialize_xref,
    serialize_basic_block,
    serialize_cfg_stats,
    serialize_symbol,
)


class TestSerializeFunction:
    """Tests for serialize_function."""

    def test_serialize_function_basic(self, angr_project_with_cfg):
        """Test serializing a function with basic attributes."""
        func = angr_project_with_cfg.kb.functions["main"]
        result = serialize_function(func)

        assert "address" in result
        assert result["address"].startswith("0x")
        assert result["name"] == "main"
        assert "size" in result
        assert "is_plt" in result
        assert result["is_plt"] is False
        assert "is_syscall" in result
        assert "is_simprocedure" in result
        assert "returning" in result
        assert "binary_name" in result
        assert "num_blocks" in result
        assert isinstance(result["num_blocks"], int)

    def test_serialize_function_with_blocks(self, angr_project_with_cfg):
        """Test serializing a function with block addresses."""
        func = angr_project_with_cfg.kb.functions["main"]
        result = serialize_function(func, include_blocks=True)

        assert "block_addresses" in result
        assert isinstance(result["block_addresses"], list)
        assert all(addr.startswith("0x") for addr in result["block_addresses"])

    def test_serialize_function_without_blocks(self, angr_project_with_cfg):
        """Test serializing a function without block addresses."""
        func = angr_project_with_cfg.kb.functions["main"]
        result = serialize_function(func, include_blocks=False)

        assert "block_addresses" not in result

    def test_serialize_plt_function(self, angr_project_with_cfg):
        """Test serializing a PLT function."""
        # Find a PLT function
        plt_func = None
        for func in angr_project_with_cfg.kb.functions.values():
            if func.is_plt:
                plt_func = func
                break

        if plt_func is None:
            pytest.skip("No PLT function found in binary")

        result = serialize_function(plt_func)
        assert result["is_plt"] is True


class TestSerializeFunctionSummary:
    """Tests for serialize_function_summary."""

    def test_serialize_function_summary(self, angr_project_with_cfg):
        """Test serializing function summary."""
        func = angr_project_with_cfg.kb.functions["main"]
        result = serialize_function_summary(func)

        assert "address" in result
        assert "name" in result
        assert "is_plt" in result
        assert "is_syscall" in result

        # Summary should not have detailed fields
        assert "size" not in result
        assert "num_blocks" not in result


class TestSerializeXref:
    """Tests for serialize_xref."""

    def test_serialize_xref(self, angr_project_with_cfg):
        """Test serializing a cross-reference."""
        # Get xrefs to main
        main_func = angr_project_with_cfg.kb.functions["main"]
        xrefs = list(
            angr_project_with_cfg.kb.xrefs.xrefs_by_dst.get(main_func.addr, set())
        )

        if not xrefs:
            pytest.skip("No xrefs found to main")

        xref = xrefs[0]
        result = serialize_xref(xref)

        assert "from_address" in result
        assert "to_address" in result
        assert "type" in result
        assert result["type"] in ("offset", "read", "write", "unknown")
        assert "block_address" in result


class TestSerializeBasicBlock:
    """Tests for serialize_basic_block."""

    def test_serialize_basic_block_with_disasm(self, angr_project_with_cfg):
        """Test serializing a basic block with disassembly."""
        func = angr_project_with_cfg.kb.functions["main"]
        blocks = list(func.blocks)

        if not blocks:
            pytest.skip("No blocks found in main")

        block = blocks[0]
        result = serialize_basic_block(block, include_disasm=True)

        assert "address" in result
        assert result["address"].startswith("0x")
        assert "size" in result
        assert "instruction_count" in result
        assert "instructions" in result

        # Check instruction structure
        if result["instructions"]:
            insn = result["instructions"][0]
            assert "address" in insn
            assert "mnemonic" in insn
            assert "op_str" in insn
            assert "bytes" in insn

    def test_serialize_basic_block_without_disasm(self, angr_project_with_cfg):
        """Test serializing a basic block without disassembly."""
        func = angr_project_with_cfg.kb.functions["main"]
        blocks = list(func.blocks)

        if not blocks:
            pytest.skip("No blocks found in main")

        block = blocks[0]
        result = serialize_basic_block(block, include_disasm=False)

        assert "address" in result
        assert "size" in result
        assert "instruction_count" in result
        assert "instructions" not in result


class TestSerializeCfgStats:
    """Tests for serialize_cfg_stats."""

    def test_serialize_cfg_stats(self, angr_project_with_cfg):
        """Test serializing CFG statistics."""
        cfg_model = angr_project_with_cfg.kb.cfgs.get_most_accurate()
        result = serialize_cfg_stats(cfg_model)

        assert "nodes" in result
        assert isinstance(result["nodes"], int)
        assert result["nodes"] > 0

        assert "edges" in result
        assert isinstance(result["edges"], int)

        assert "normalized" in result
        assert "memory_data_count" in result
        assert "jump_table_count" in result


class TestSerializeSymbol:
    """Tests for serialize_symbol."""

    def test_serialize_symbol(self, angr_project):
        """Test serializing a symbol."""
        main_obj = angr_project.loader.main_object

        # Find an export symbol
        export_sym = None
        if hasattr(main_obj, "symbols"):
            for sym in main_obj.symbols:
                if sym.is_export and sym.name:
                    export_sym = sym
                    break

        if export_sym is None:
            pytest.skip("No export symbol found")

        result = serialize_symbol(export_sym)

        assert "name" in result
        assert "address" in result
        assert result["address"].startswith("0x")
        assert "size" in result
        assert "is_function" in result
        assert "is_import" in result
        assert "is_export" in result
        assert result["is_export"] is True
