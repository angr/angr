from __future__ import annotations

import pytest

from angr.mcp.server import (
    load_binary,
    get_cfg,
    list_functions,
    get_function_info,
    decompile_function,
    get_xrefs,
    get_strings,
    get_imports,
    get_exports,
    get_basic_blocks,
    get_callgraph,
    find_functions_by_pattern,
    list_projects,
    close_project,
)
from angr.mcp.exceptions import (
    ProjectNotFoundError,
    CFGNotBuiltError,
    FunctionNotFoundError,
)
from angr.mcp.session import get_session_manager


@pytest.fixture(autouse=True)
def cleanup_sessions():
    """Clean up all sessions after each test."""
    yield
    manager = get_session_manager()
    for project_id in list(manager._sessions.keys()):
        manager.close_session(project_id)


class TestLoadBinary:
    """Tests for the load_binary tool."""

    def test_load_binary_success(self, binary_path):
        """Test loading a binary successfully."""
        result = load_binary(binary_path)

        assert "project_id" in result
        assert len(result["project_id"]) == 8
        assert result["arch"] == "AMD64"
        assert result["bits"] == 64
        assert result["endianness"] == "little"
        assert "entry_point" in result
        assert result["entry_point"].startswith("0x")

    def test_load_binary_i386(self, i386_binary_path):
        """Test loading an i386 binary."""
        result = load_binary(i386_binary_path)

        assert result["arch"] == "X86"
        assert result["bits"] == 32

    def test_load_binary_auto_load_libs_false(self, binary_path):
        """Test loading with auto_load_libs=False."""
        result = load_binary(binary_path, auto_load_libs=False)

        assert "project_id" in result

    def test_load_binary_file_not_found(self):
        """Test loading a nonexistent binary."""
        with pytest.raises(FileNotFoundError):
            load_binary("/nonexistent/path/to/binary")


class TestGetCfg:
    """Tests for the get_cfg tool."""

    def test_get_cfg_success(self, binary_path):
        """Test building CFG successfully."""
        load_result = load_binary(binary_path)
        project_id = load_result["project_id"]

        result = get_cfg(project_id)

        assert result["status"] == "success"
        assert "nodes" in result
        assert result["nodes"] > 0
        assert "edges" in result
        assert "functions_discovered" in result
        assert result["functions_discovered"] > 0

    def test_get_cfg_cached(self, binary_path):
        """Test that calling get_cfg twice returns cached result."""
        load_result = load_binary(binary_path)
        project_id = load_result["project_id"]

        result1 = get_cfg(project_id)
        result2 = get_cfg(project_id)

        # Should return same statistics
        assert result1["nodes"] == result2["nodes"]
        assert result1["edges"] == result2["edges"]

    def test_get_cfg_project_not_found(self):
        """Test get_cfg with invalid project_id."""
        with pytest.raises(ProjectNotFoundError):
            get_cfg("nonexistent")

    def test_get_cfg_with_options(self, binary_path):
        """Test get_cfg with different options."""
        load_result = load_binary(binary_path)
        project_id = load_result["project_id"]

        result = get_cfg(project_id, normalize=True, data_references=True)

        assert result["status"] == "success"
        assert result["normalized"] is True


class TestListFunctions:
    """Tests for the list_functions tool."""

    def test_list_functions_success(self, binary_path):
        """Test listing functions successfully."""
        load_result = load_binary(binary_path)
        project_id = load_result["project_id"]
        get_cfg(project_id)

        result = list_functions(project_id)

        assert "total" in result
        assert result["total"] > 0
        assert "functions" in result
        assert len(result["functions"]) > 0

        # Check function structure
        func = result["functions"][0]
        assert "address" in func
        assert "name" in func
        assert "is_plt" in func
        assert "is_syscall" in func

    def test_list_functions_pagination(self, binary_path):
        """Test pagination of function list."""
        load_result = load_binary(binary_path)
        project_id = load_result["project_id"]
        get_cfg(project_id)

        result1 = list_functions(project_id, limit=5, offset=0)
        result2 = list_functions(project_id, limit=5, offset=5)

        assert len(result1["functions"]) == 5
        assert len(result2["functions"]) == 5

        # Should be different functions
        addrs1 = {f["address"] for f in result1["functions"]}
        addrs2 = {f["address"] for f in result2["functions"]}
        assert addrs1.isdisjoint(addrs2)

    def test_list_functions_filter_plt(self, binary_path):
        """Test filtering PLT functions."""
        load_result = load_binary(binary_path)
        project_id = load_result["project_id"]
        get_cfg(project_id)

        # Get only PLT
        result = list_functions(project_id, filter_plt=True)
        for func in result["functions"]:
            assert func["is_plt"] is True

        # Exclude PLT
        result = list_functions(project_id, filter_plt=False)
        for func in result["functions"]:
            assert func["is_plt"] is False

    def test_list_functions_name_pattern(self, binary_path):
        """Test filtering by name pattern."""
        load_result = load_binary(binary_path)
        project_id = load_result["project_id"]
        get_cfg(project_id)

        result = list_functions(project_id, name_pattern="main")

        assert result["total"] >= 1
        for func in result["functions"]:
            assert "main" in func["name"].lower()

    def test_list_functions_cfg_required(self, binary_path):
        """Test that list_functions requires CFG."""
        load_result = load_binary(binary_path)
        project_id = load_result["project_id"]

        with pytest.raises(CFGNotBuiltError):
            list_functions(project_id)


class TestGetFunctionInfo:
    """Tests for the get_function_info tool."""

    def test_get_function_info_by_name(self, binary_path):
        """Test getting function info by name."""
        load_result = load_binary(binary_path)
        project_id = load_result["project_id"]
        get_cfg(project_id)

        result = get_function_info(project_id, name="main")

        assert result["name"] == "main"
        assert "address" in result
        assert "size" in result
        assert "num_blocks" in result

    def test_get_function_info_by_address(self, binary_path):
        """Test getting function info by address."""
        load_result = load_binary(binary_path)
        project_id = load_result["project_id"]
        get_cfg(project_id)

        # First get main's address
        main_info = get_function_info(project_id, name="main")
        main_addr = main_info["address"]

        # Now look up by address
        result = get_function_info(project_id, address=main_addr)

        assert result["address"] == main_addr
        assert result["name"] == "main"

    def test_get_function_info_include_blocks(self, binary_path):
        """Test getting function info with blocks."""
        load_result = load_binary(binary_path)
        project_id = load_result["project_id"]
        get_cfg(project_id)

        result = get_function_info(project_id, name="main", include_blocks=True)

        assert "block_addresses" in result
        assert len(result["block_addresses"]) == result["num_blocks"]

    def test_get_function_info_not_found(self, binary_path):
        """Test getting info for nonexistent function."""
        load_result = load_binary(binary_path)
        project_id = load_result["project_id"]
        get_cfg(project_id)

        with pytest.raises(FunctionNotFoundError):
            get_function_info(project_id, name="nonexistent_function_xyz")

    def test_get_function_info_no_params(self, binary_path):
        """Test that address or name is required."""
        load_result = load_binary(binary_path)
        project_id = load_result["project_id"]
        get_cfg(project_id)

        with pytest.raises(ValueError):
            get_function_info(project_id)


class TestDecompileFunction:
    """Tests for the decompile_function tool."""

    def test_decompile_function_by_name(self, binary_path):
        """Test decompiling a function by name."""
        load_result = load_binary(binary_path)
        project_id = load_result["project_id"]
        get_cfg(project_id)

        result = decompile_function(project_id, name="main")

        assert "code" in result
        assert len(result["code"]) > 0
        assert result["function_name"] == "main"
        assert "function_address" in result

    def test_decompile_function_by_address(self, binary_path):
        """Test decompiling a function by address."""
        load_result = load_binary(binary_path)
        project_id = load_result["project_id"]
        get_cfg(project_id)

        # Get main's address
        main_info = get_function_info(project_id, name="main")
        main_addr = main_info["address"]

        result = decompile_function(project_id, address=main_addr)

        assert "code" in result
        assert result["function_address"] == main_addr

    def test_decompile_function_not_found(self, binary_path):
        """Test decompiling nonexistent function."""
        load_result = load_binary(binary_path)
        project_id = load_result["project_id"]
        get_cfg(project_id)

        with pytest.raises(FunctionNotFoundError):
            decompile_function(project_id, name="nonexistent_xyz")

    def test_decompile_function_no_params(self, binary_path):
        """Test that address or name is required."""
        load_result = load_binary(binary_path)
        project_id = load_result["project_id"]
        get_cfg(project_id)

        with pytest.raises(ValueError):
            decompile_function(project_id)


class TestGetXrefs:
    """Tests for the get_xrefs tool."""

    def test_get_xrefs_to(self, binary_path):
        """Test getting xrefs to an address."""
        load_result = load_binary(binary_path)
        project_id = load_result["project_id"]
        get_cfg(project_id)

        main_info = get_function_info(project_id, name="main")
        main_addr = main_info["address"]

        result = get_xrefs(project_id, address=main_addr, direction="to")

        assert "xrefs" in result
        assert result["direction"] == "to"
        assert result["address"] == main_addr

    def test_get_xrefs_from(self, binary_path):
        """Test getting xrefs from an address."""
        load_result = load_binary(binary_path)
        project_id = load_result["project_id"]
        get_cfg(project_id)

        main_info = get_function_info(project_id, name="main")
        main_addr = main_info["address"]

        result = get_xrefs(project_id, address=main_addr, direction="from")

        assert "xrefs" in result
        assert result["direction"] == "from"

    def test_get_xrefs_invalid_direction(self, binary_path):
        """Test invalid direction parameter."""
        load_result = load_binary(binary_path)
        project_id = load_result["project_id"]
        get_cfg(project_id)

        with pytest.raises(ValueError):
            get_xrefs(project_id, address="0x400000", direction="invalid")


class TestGetStrings:
    """Tests for the get_strings tool."""

    def test_get_strings_success(self, binary_path):
        """Test extracting strings."""
        load_result = load_binary(binary_path)
        project_id = load_result["project_id"]
        get_cfg(project_id, data_references=True)

        result = get_strings(project_id)

        assert "strings" in result
        assert "count" in result

        if result["count"] > 0:
            string_entry = result["strings"][0]
            assert "address" in string_entry
            assert "content" in string_entry
            assert "size" in string_entry

    def test_get_strings_min_length(self, binary_path):
        """Test min_length filter."""
        load_result = load_binary(binary_path)
        project_id = load_result["project_id"]
        get_cfg(project_id, data_references=True)

        result = get_strings(project_id, min_length=10)

        for s in result["strings"]:
            assert len(s["content"]) >= 10

    def test_get_strings_limit(self, binary_path):
        """Test limit parameter."""
        load_result = load_binary(binary_path)
        project_id = load_result["project_id"]
        get_cfg(project_id, data_references=True)

        result = get_strings(project_id, limit=5)

        assert len(result["strings"]) <= 5


class TestGetImports:
    """Tests for the get_imports tool."""

    def test_get_imports_success(self, binary_path):
        """Test getting imports."""
        load_result = load_binary(binary_path)
        project_id = load_result["project_id"]

        result = get_imports(project_id)

        assert "imports" in result
        assert "count" in result
        assert result["count"] > 0

        # Check import structure
        imp = result["imports"][0]
        assert "name" in imp
        assert "resolved" in imp


class TestGetExports:
    """Tests for the get_exports tool."""

    def test_get_exports_success(self, binary_path):
        """Test getting exports."""
        load_result = load_binary(binary_path)
        project_id = load_result["project_id"]

        result = get_exports(project_id)

        assert "exports" in result
        assert "count" in result

        if result["count"] > 0:
            exp = result["exports"][0]
            assert "name" in exp
            assert "address" in exp


class TestGetBasicBlocks:
    """Tests for the get_basic_blocks tool."""

    def test_get_basic_blocks_success(self, binary_path):
        """Test getting basic blocks."""
        load_result = load_binary(binary_path)
        project_id = load_result["project_id"]
        get_cfg(project_id)

        main_info = get_function_info(project_id, name="main")
        main_addr = main_info["address"]

        result = get_basic_blocks(project_id, function_address=main_addr)

        assert result["function_name"] == "main"
        assert "blocks" in result
        assert result["block_count"] > 0

        # Check block structure
        block = result["blocks"][0]
        assert "address" in block
        assert "size" in block
        assert "instruction_count" in block
        assert "instructions" in block

    def test_get_basic_blocks_without_disasm(self, binary_path):
        """Test getting blocks without disassembly."""
        load_result = load_binary(binary_path)
        project_id = load_result["project_id"]
        get_cfg(project_id)

        main_info = get_function_info(project_id, name="main")
        main_addr = main_info["address"]

        result = get_basic_blocks(project_id, function_address=main_addr, include_disasm=False)

        block = result["blocks"][0]
        assert "instructions" not in block

    def test_get_basic_blocks_function_not_found(self, binary_path):
        """Test with invalid function address."""
        load_result = load_binary(binary_path)
        project_id = load_result["project_id"]
        get_cfg(project_id)

        with pytest.raises(FunctionNotFoundError):
            get_basic_blocks(project_id, function_address="0xdeadbeef")


class TestGetCallgraph:
    """Tests for the get_callgraph tool."""

    def test_get_callgraph_full(self, binary_path):
        """Test getting full callgraph."""
        load_result = load_binary(binary_path)
        project_id = load_result["project_id"]
        get_cfg(project_id)

        result = get_callgraph(project_id)

        assert "nodes" in result
        assert "edges" in result
        assert result["node_count"] > 0

        # Check node structure
        node = result["nodes"][0]
        assert "address" in node
        assert "name" in node
        assert "is_plt" in node

    def test_get_callgraph_from_root(self, binary_path):
        """Test getting callgraph from a root function."""
        load_result = load_binary(binary_path)
        project_id = load_result["project_id"]
        get_cfg(project_id)

        main_info = get_function_info(project_id, name="main")
        main_addr = main_info["address"]

        result = get_callgraph(project_id, root_address=main_addr)

        # Should contain main
        addresses = {n["address"] for n in result["nodes"]}
        assert main_addr in addresses

    def test_get_callgraph_with_depth(self, binary_path):
        """Test callgraph with max depth."""
        load_result = load_binary(binary_path)
        project_id = load_result["project_id"]
        get_cfg(project_id)

        main_info = get_function_info(project_id, name="main")
        main_addr = main_info["address"]

        result1 = get_callgraph(project_id, root_address=main_addr, max_depth=1)
        result2 = get_callgraph(project_id, root_address=main_addr, max_depth=3)

        # Deeper should have more or equal nodes
        assert result2["node_count"] >= result1["node_count"]


class TestFindFunctionsByPattern:
    """Tests for the find_functions_by_pattern tool."""

    def test_find_functions_contains(self, binary_path):
        """Test finding functions with contains pattern."""
        load_result = load_binary(binary_path)
        project_id = load_result["project_id"]
        get_cfg(project_id)

        result = find_functions_by_pattern(project_id, pattern="sub_", search_type="contains")

        assert "functions" in result
        for func in result["functions"]:
            assert "sub_" in func["name"].lower()

    def test_find_functions_startswith(self, binary_path):
        """Test finding functions with startswith pattern."""
        load_result = load_binary(binary_path)
        project_id = load_result["project_id"]
        get_cfg(project_id)

        result = find_functions_by_pattern(project_id, pattern="sub_", search_type="startswith")

        for func in result["functions"]:
            assert func["name"].lower().startswith("sub_")

    def test_find_functions_regex(self, binary_path):
        """Test finding functions with regex pattern."""
        load_result = load_binary(binary_path)
        project_id = load_result["project_id"]
        get_cfg(project_id)

        result = find_functions_by_pattern(project_id, pattern=r"^sub_[0-9a-f]+$", search_type="regex")

        assert result["count"] >= 0

    def test_find_functions_invalid_search_type(self, binary_path):
        """Test invalid search type."""
        load_result = load_binary(binary_path)
        project_id = load_result["project_id"]
        get_cfg(project_id)

        with pytest.raises(ValueError):
            find_functions_by_pattern(project_id, pattern="test", search_type="invalid")

    def test_find_functions_invalid_regex(self, binary_path):
        """Test invalid regex pattern."""
        load_result = load_binary(binary_path)
        project_id = load_result["project_id"]
        get_cfg(project_id)

        with pytest.raises(ValueError):
            find_functions_by_pattern(project_id, pattern="[invalid", search_type="regex")


class TestListProjects:
    """Tests for the list_projects tool."""

    def test_list_projects_empty(self):
        """Test listing when no projects loaded."""
        result = list_projects()

        assert result["count"] == 0
        assert result["projects"] == []

    def test_list_projects_with_projects(self, binary_path, i386_binary_path):
        """Test listing multiple projects."""
        load_binary(binary_path)
        load_binary(i386_binary_path)

        result = list_projects()

        assert result["count"] == 2
        assert len(result["projects"]) == 2


class TestCloseProject:
    """Tests for the close_project tool."""

    def test_close_project_success(self, binary_path):
        """Test closing a project."""
        load_result = load_binary(binary_path)
        project_id = load_result["project_id"]

        result = close_project(project_id)

        assert result["closed"] is True

        # Verify it's gone
        projects = list_projects()
        assert project_id not in [p["project_id"] for p in projects["projects"]]

    def test_close_project_not_found(self):
        """Test closing nonexistent project."""
        result = close_project("nonexistent")

        assert result["closed"] is False


class TestIntegration:
    """Integration tests for the MCP server."""

    def test_full_analysis_workflow(self, binary_path):
        """Test a complete analysis workflow."""
        # Load binary
        load_result = load_binary(binary_path)
        project_id = load_result["project_id"]
        assert load_result["arch"] == "AMD64"

        # Build CFG
        cfg_result = get_cfg(project_id)
        assert cfg_result["functions_discovered"] > 0

        # List functions
        funcs_result = list_functions(project_id)
        assert funcs_result["total"] > 0

        # Get function info
        info_result = get_function_info(project_id, name="main")
        assert info_result["name"] == "main"

        # Decompile
        dec_result = decompile_function(project_id, name="main")
        assert len(dec_result["code"]) > 0

        # Get strings
        strings_result = get_strings(project_id)
        assert "strings" in strings_result

        # Get imports/exports
        imports_result = get_imports(project_id)
        assert imports_result["count"] > 0

        exports_result = get_exports(project_id)
        assert "exports" in exports_result

        # Get callgraph
        cg_result = get_callgraph(project_id, root_address=info_result["address"])
        assert cg_result["node_count"] > 0

        # Close project
        close_result = close_project(project_id)
        assert close_result["closed"] is True

    def test_multiple_projects_isolation(self, binary_path, i386_binary_path):
        """Test that multiple projects are isolated."""
        # Load two different binaries
        result1 = load_binary(binary_path)
        result2 = load_binary(i386_binary_path)

        project_id1 = result1["project_id"]
        project_id2 = result2["project_id"]

        # Build CFG for both
        get_cfg(project_id1)
        get_cfg(project_id2)

        # Get functions from each
        funcs1 = list_functions(project_id1)
        funcs2 = list_functions(project_id2)

        # Should have different function counts (different binaries)
        # Just verify they both work independently
        assert funcs1["total"] > 0
        assert funcs2["total"] > 0

        # Verify architectures are different
        assert result1["arch"] == "AMD64"
        assert result2["arch"] == "X86"

        # Close both
        close_project(project_id1)
        close_project(project_id2)

        # Verify both are gone
        projects = list_projects()
        assert projects["count"] == 0
