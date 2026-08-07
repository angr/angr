"""Main MCP server for angr binary analysis."""

from __future__ import annotations

import contextlib
import functools
import inspect
import logging
import re
import sys
from typing import Any

import networkx as nx
from fastmcp import FastMCP
from fastmcp.exceptions import ToolError
from fastmcp.server.middleware import CallNext, Middleware, MiddlewareContext

from angr.analyses.decompiler.edits import DecompilationEditError, parse_address, resolve_function
from angr.knowledge_plugins.cfg.memory_data import MemoryDataSort
from angr.knowledge_plugins.functions import Function
from angr.utils.mp import protect_stdio_from_forked_children

from .errors import (
    CFGNotBuiltError,
    DecompilationError,
    FunctionNotFoundError,
    InvalidArgumentError,
    ProjectNotFoundError,
)
from .serializers import (
    serialize_basic_block,
    serialize_cfg_stats,
    serialize_function,
    serialize_function_summary,
    serialize_symbol,
    serialize_xref,
)
from .session import ProjectSession, get_session_manager

l = logging.getLogger(__name__)


class StdoutGuardMiddleware(Middleware):
    """
    Keep analysis output off of stdout.

    Under the stdio transport, stdout is the JSON-RPC channel. This middleware redirects stdout to
    stderr to avoid messing with the stdio transport.
    """

    async def on_message(self, context: MiddlewareContext[Any], call_next: CallNext[Any, Any]) -> Any:
        with contextlib.redirect_stdout(sys.stderr):
            return await call_next(context)


# Worker processes should not inherit stdio.
protect_stdio_from_forked_children()

# Create the FastMCP server instance
mcp = FastMCP("angr-mcp", instructions="Binary analysis server powered by angr")
mcp.add_middleware(StdoutGuardMiddleware())


def _get_session(project_id: str) -> ProjectSession:
    """Helper to get session with proper error handling."""
    try:
        return get_session_manager().get_session(project_id)
    except KeyError as e:
        raise ProjectNotFoundError(str(e)) from e


def _require_cfg(session: ProjectSession) -> None:
    """Helper to ensure CFG exists."""
    if not session.has_cfg:
        raise CFGNotBuiltError(f"CFG not built for project {session.project_id}. Call get_cfg first.")


def _parse_address(address: str | int) -> int:
    """Parse an address given as an int or a string. Accepts 0x-prefixed hex and decimal."""
    return parse_address(address)


def _find_function(session: ProjectSession, address: str | int | None = None, name: str | None = None) -> Function:
    """Find a function by address or name. Any address inside the function resolves to it."""
    if address is None and name is None:
        raise InvalidArgumentError("Must specify either 'address' or 'name'")
    try:
        return resolve_function(session.project.kb, address=address, name=name)
    except DecompilationEditError as e:
        raise FunctionNotFoundError(str(e)) from e


def _as_tool_error(func):
    """
    Convert this layer's exceptions into fastmcp ToolErrors.

    FastMCP masks the message of any exception that is not a ToolError, so without this a caller
    sees a generic failure instead of "no function named 'foo'" or the list of valid variable names.
    """

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except ToolError:
            raise
        except DecompilationEditError as e:
            raise ToolError(str(e)) from e

    return wrapper


def _serialized(func):
    """
    Hold the project's lock for the duration of a tool call.

    FastMCP dispatches synchronous tools onto worker threads, so two calls can reach one Project at
    the same time. Applied to every tool, including read-only ones: the decompilation and variable
    caches spill to LMDB, and a read racing an eviction is the same hazard as a concurrent write.
    """
    signature = inspect.signature(func)

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        try:
            bound = signature.bind(*args, **kwargs)
        except TypeError:
            return func(*args, **kwargs)
        project_id = bound.arguments.get("project_id")
        if project_id is None:
            return func(*args, **kwargs)
        try:
            session = get_session_manager().get_session(project_id)
        except KeyError:
            # let the tool itself raise the project-not-found error
            return func(*args, **kwargs)
        with session.exclusive():
            return func(*args, **kwargs)

    return wrapper


# ============================================================================
# Core Tools
# ============================================================================


@mcp.tool()
@_as_tool_error
@_serialized
def load_binary(
    binary_path: str,
    auto_load_libs: bool = False,
) -> dict[str, Any]:
    """
    Load a binary file as an angr Project for analysis.

    This is typically the first tool to call. It creates a new analysis
    session and returns a project_id that must be used for subsequent operations.

    Args:
        binary_path: Absolute path to the binary file to analyze
        auto_load_libs: Whether to automatically load shared libraries (default: False)

    Returns:
        Project information including project_id, architecture, and entry point
    """
    manager = get_session_manager()

    session = manager.create_session(
        binary_path,
        auto_load_libs=auto_load_libs,
    )

    proj = session.project

    return {
        "project_id": session.project_id,
        "binary_path": session.binary_path,
        "arch": proj.arch.name,
        "bits": proj.arch.bits,
        "endianness": "little" if proj.arch.memory_endness == "Iend_LE" else "big",
        "entry_point": hex(proj.entry),
        "filename": proj.filename,
    }


@mcp.tool()
@_as_tool_error
@_serialized
def get_cfg(
    project_id: str,
    normalize: bool = True,
    data_references: bool = True,
) -> dict[str, Any]:
    """
    Build or retrieve the Control Flow Graph (CFG) for a project.

    The CFG is required for most analysis operations including function
    discovery, decompilation, and cross-reference analysis.

    Args:
        project_id: The project ID returned by load_binary
        normalize: Whether to normalize the CFG (recommended: True)
        data_references: Whether to collect data references (for string analysis)

    Returns:
        CFG statistics including node/edge counts and functions discovered
    """
    session = _get_session(project_id)
    proj = session.project

    # Build CFG if not already built
    if not session.has_cfg:
        l.info("Building CFG for project %s", project_id)
        cfg = proj.analyses.CFGFast(
            normalize=normalize,
            data_references=data_references,
        )
        session.cfg = cfg.model

    assert session.cfg is not None
    return {
        "project_id": project_id,
        "status": "success",
        **serialize_cfg_stats(session.cfg),
        "functions_discovered": len(proj.kb.functions),
    }


@mcp.tool()
@_as_tool_error
@_serialized
def recover_calling_conventions(
    project_id: str,
    workers: int = 0,
    force: bool = False,
) -> dict[str, Any]:
    """
    Recover calling conventions and prototypes for every function in the binary.

    Requires CFG to be built first via get_cfg. This improves the quality of decompilation output, especially the
    arguments shown at call sites.

    Args:
        project_id: The project ID
        workers: Number of worker processes to use (0 = run in-process, the default)
        force: Re-analyze functions that already have a calling convention or prototype

    Returns:
        Number of functions for which a calling convention was recovered
    """
    session = _get_session(project_id)
    _require_cfg(session)
    proj = session.project

    if workers < 0:
        raise InvalidArgumentError("workers must be >= 0")

    analysis = proj.analyses.CompleteCallingConventions(
        cfg=session.cfg,
        analyze_callsites=True,
        workers=workers,
        force=force,
    )

    recovered = sum(1 for func in proj.kb.functions.values() if func.calling_convention is not None)
    return {
        "project_id": project_id,
        "workers": workers,
        "functions_analyzed": len(proj.kb.functions),
        "functions_with_calling_convention": recovered,
        "prototype_libnames": sorted(analysis.prototype_libnames),
    }


@mcp.tool()
@_as_tool_error
@_serialized
def list_functions(
    project_id: str,
    filter_plt: bool | None = None,
    filter_syscall: bool | None = None,
    name_pattern: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> dict[str, Any]:
    """
    List all functions discovered in the binary.

    Requires CFG to be built first via get_cfg.

    Args:
        project_id: The project ID
        filter_plt: If True, only show PLT stubs; if False, exclude them
        filter_syscall: If True, only show syscalls; if False, exclude them
        name_pattern: Filter functions by name substring (case-insensitive)
        limit: Maximum number of functions to return (default: 100)
        offset: Number of functions to skip (for pagination)

    Returns:
        List of function summaries with addresses and names
    """
    session = _get_session(project_id)
    _require_cfg(session)

    functions = []
    for func in session.project.kb.functions.values():
        # Apply filters
        if filter_plt is not None and func.is_plt != filter_plt:
            continue
        if filter_syscall is not None and func.is_syscall != filter_syscall:
            continue
        if name_pattern and name_pattern.lower() not in func.name.lower():
            continue

        functions.append(serialize_function_summary(func))

    # Sort by address
    functions.sort(key=lambda f: int(f["address"], 16))

    # Apply pagination
    total = len(functions)
    functions = functions[offset : offset + limit]

    return {
        "project_id": project_id,
        "total": total,
        "offset": offset,
        "limit": limit,
        "functions": functions,
    }


@mcp.tool()
@_as_tool_error
@_serialized
def get_function_info(
    project_id: str,
    address: str | None = None,
    name: str | None = None,
    include_blocks: bool = False,
) -> dict[str, Any]:
    """
    Get detailed information about a specific function.

    Specify either address (hex string like "0x401000") or function name.

    Args:
        project_id: The project ID
        address: Function address as hex string (e.g., "0x401000")
        name: Function name to look up
        include_blocks: Whether to include list of basic block addresses

    Returns:
        Detailed function information including size, complexity, etc.
    """
    session = _get_session(project_id)
    _require_cfg(session)

    func = _find_function(session, address=address, name=name)

    return {
        "project_id": project_id,
        **serialize_function(func, include_blocks=include_blocks),
    }


@mcp.tool()
@_as_tool_error
@_serialized
def decompile_function(
    project_id: str,
    address: str | None = None,
    name: str | None = None,
) -> dict[str, Any]:
    """
    Decompile a function to C-like pseudocode.

    Specify either address (hex string) or function name.

    Args:
        project_id: The project ID
        address: Function address as hex string (e.g., "0x401000")
        name: Function name to decompile

    Returns:
        Decompiled pseudocode and function metadata
    """
    session = _get_session(project_id)
    _require_cfg(session)
    proj = session.project

    func = _find_function(session, address=address, name=name)

    # Decompile
    try:
        dec = proj.analyses.Decompiler(func)

        if dec.codegen is None:
            raise DecompilationError(f"Decompilation failed for {func.name}: no code generated")

        return {
            "project_id": project_id,
            "function_address": hex(func.addr),
            "function_name": func.name,
            "code": dec.codegen.text,
        }
    except DecompilationError:
        raise
    except Exception as e:
        raise DecompilationError(f"Decompilation failed: {e}") from e


@mcp.tool()
@_as_tool_error
@_serialized
def get_xrefs(
    project_id: str,
    address: str,
    direction: str = "to",
) -> dict[str, Any]:
    """
    Get cross-references to or from a specific address.

    Args:
        project_id: The project ID
        address: The address to query (hex string, e.g., "0x401000")
        direction: "to" for references TO this address, "from" for references FROM this address

    Returns:
        List of cross-references with source/destination and type
    """
    session = _get_session(project_id)
    _require_cfg(session)

    addr = _parse_address(address)
    xref_manager = session.project.kb.xrefs

    if direction == "to":
        xrefs = list(xref_manager.xrefs_by_dst.get(addr, set()))
    elif direction == "from":
        xrefs = list(xref_manager.xrefs_by_ins_addr.get(addr, set()))
    else:
        raise InvalidArgumentError(f"Invalid direction: {direction}. Use 'to' or 'from'.")

    return {
        "project_id": project_id,
        "address": hex(addr),
        "direction": direction,
        "count": len(xrefs),
        "xrefs": [serialize_xref(x) for x in xrefs],
    }


# ============================================================================
# Additional Useful Tools
# ============================================================================


@mcp.tool()
@_as_tool_error
@_serialized
def get_strings(
    project_id: str,
    min_length: int = 4,
    limit: int = 100,
) -> dict[str, Any]:
    """
    Extract strings from the binary.

    Requires CFG with data_references=True.

    Args:
        project_id: The project ID
        min_length: Minimum string length to include (default: 4)
        limit: Maximum number of strings to return (default: 100)

    Returns:
        List of strings with their addresses
    """
    session = _get_session(project_id)
    _require_cfg(session)
    assert session.cfg is not None

    strings = []
    for md in session.cfg.memory_data.values():
        if md.sort not in (MemoryDataSort.String, MemoryDataSort.UnicodeString):
            continue

        if md.content is None:
            try:
                md.fill_content(session.project.loader)
            except KeyError:
                continue

        if md.content and len(md.content) >= min_length:
            try:
                content = md.content.decode("utf-8", errors="replace").rstrip("\x00")
                if len(content) >= min_length:
                    strings.append(
                        {
                            "address": hex(md.addr),
                            "content": content,
                            "size": md.size,
                            "type": ("unicode" if md.sort == MemoryDataSort.UnicodeString else "ascii"),
                        }
                    )
            except UnicodeDecodeError:
                continue

        if len(strings) >= limit:
            break

    return {
        "project_id": project_id,
        "count": len(strings),
        "strings": strings,
    }


@mcp.tool()
@_as_tool_error
@_serialized
def get_imports(project_id: str) -> dict[str, Any]:
    """
    List imported symbols (external functions/variables the binary depends on).

    Args:
        project_id: The project ID

    Returns:
        List of imported symbols with their names and addresses
    """
    session = _get_session(project_id)
    proj = session.project

    imports = []
    main_obj = proj.loader.main_object

    if hasattr(main_obj, "imports"):
        for name, reloc in main_obj.imports.items():
            import_info: dict[str, Any] = {
                "name": name,
                "resolved": reloc.resolved,
            }
            if reloc.symbol:
                import_info["address"] = hex(reloc.symbol.rebased_addr) if reloc.symbol.rebased_addr else None
            if hasattr(reloc, "resolvewith") and reloc.resolvewith:
                import_info["library"] = reloc.resolvewith
            imports.append(import_info)

    return {
        "project_id": project_id,
        "count": len(imports),
        "imports": imports,
    }


@mcp.tool()
@_as_tool_error
@_serialized
def get_exports(project_id: str) -> dict[str, Any]:
    """
    List exported symbols (functions/variables this binary provides).

    Args:
        project_id: The project ID

    Returns:
        List of exported symbols with their names and addresses
    """
    session = _get_session(project_id)
    proj = session.project

    exports = []
    main_obj = proj.loader.main_object

    if hasattr(main_obj, "symbols"):
        for sym in main_obj.symbols:
            if sym.is_export:
                exports.append(serialize_symbol(sym))

    return {
        "project_id": project_id,
        "count": len(exports),
        "exports": exports,
    }


@mcp.tool()
@_as_tool_error
@_serialized
def get_basic_blocks(
    project_id: str,
    function_address: str,
    include_disasm: bool = True,
) -> dict[str, Any]:
    """
    Get all basic blocks for a function.

    Args:
        project_id: The project ID
        function_address: Function address as hex string
        include_disasm: Whether to include disassembly for each block

    Returns:
        List of basic blocks with their instructions
    """
    session = _get_session(project_id)
    _require_cfg(session)

    addr = _parse_address(function_address)
    func = session.project.kb.functions.get(addr)

    if func is None:
        raise FunctionNotFoundError(f"Function not found at {function_address}")

    blocks = []
    for block in func.blocks:
        blocks.append(serialize_basic_block(block, include_disasm=include_disasm))

    return {
        "project_id": project_id,
        "function_address": hex(addr),
        "function_name": func.name,
        "block_count": len(blocks),
        "blocks": blocks,
    }


@mcp.tool()
@_as_tool_error
@_serialized
def get_callgraph(
    project_id: str,
    max_depth: int | None = None,
    root_address: str | None = None,
) -> dict[str, Any]:
    """
    Get the function call graph.

    Args:
        project_id: The project ID
        max_depth: Maximum depth from root (None for full graph)
        root_address: Optional starting function address for subgraph

    Returns:
        Call graph as nodes and edges
    """
    session = _get_session(project_id)
    _require_cfg(session)

    cg = session.project.kb.functions.callgraph

    # If root specified, extract subgraph
    if root_address:
        root_addr = _parse_address(root_address)
        if root_addr not in cg:
            raise FunctionNotFoundError(f"Function at {root_address} not found in callgraph")

        if max_depth:
            # BFS to get nodes within depth
            nodes = set()
            current_level = {root_addr}
            for _ in range(max_depth + 1):
                nodes.update(current_level)
                next_level = set()
                for node in current_level:
                    if node in cg:
                        next_level.update(cg.successors(node))
                current_level = next_level - nodes
            cg = cg.subgraph(nodes)
        else:
            # All descendants
            descendants = nx.descendants(cg, root_addr)
            descendants.add(root_addr)
            cg = cg.subgraph(descendants)

    # Build nodes list
    func_manager = session.project.kb.functions
    nodes = []
    for addr in cg.nodes():
        func = func_manager.get(addr)
        if func:
            nodes.append(
                {
                    "address": hex(addr),
                    "name": func.name,
                    "is_plt": func.is_plt,
                }
            )

    # Build edges list
    edges = []
    for src, dst in cg.edges():
        edges.append(
            {
                "from": hex(src),
                "to": hex(dst),
            }
        )

    return {
        "project_id": project_id,
        "node_count": len(nodes),
        "edge_count": len(edges),
        "nodes": nodes,
        "edges": edges,
    }


@mcp.tool()
@_as_tool_error
@_serialized
def find_functions_by_pattern(
    project_id: str,
    pattern: str,
    search_type: str = "contains",
) -> dict[str, Any]:
    """
    Search for functions by name pattern.

    Args:
        project_id: The project ID
        pattern: Search pattern (depends on search_type)
        search_type: "contains", "startswith", "endswith", or "regex"

    Returns:
        List of matching functions
    """
    session = _get_session(project_id)
    _require_cfg(session)

    matches = []
    pattern_lower = pattern.lower()

    for func in session.project.kb.functions.values():
        name_lower = func.name.lower()

        match = False
        if search_type == "contains":
            match = pattern_lower in name_lower
        elif search_type == "startswith":
            match = name_lower.startswith(pattern_lower)
        elif search_type == "endswith":
            match = name_lower.endswith(pattern_lower)
        elif search_type == "regex":
            try:
                match = bool(re.search(pattern, func.name, re.IGNORECASE))
            except re.error as e:
                raise InvalidArgumentError(f"Invalid regex pattern: {pattern}") from e
        else:
            raise InvalidArgumentError(f"Invalid search_type: {search_type}")

        if match:
            matches.append(serialize_function_summary(func))

    return {
        "project_id": project_id,
        "pattern": pattern,
        "search_type": search_type,
        "count": len(matches),
        "functions": matches,
    }


@mcp.tool()
@_as_tool_error
@_serialized
def list_projects() -> dict[str, Any]:
    """
    List all currently loaded projects/sessions.

    Returns:
        List of active project sessions with their IDs and metadata
    """
    manager = get_session_manager()
    sessions = manager.list_sessions()

    return {
        "count": len(sessions),
        "projects": sessions,
    }


@mcp.tool()
@_as_tool_error
@_serialized
def close_project(project_id: str) -> dict[str, Any]:
    """
    Close a project and free its resources.

    Args:
        project_id: The project ID to close

    Returns:
        Confirmation of closure
    """
    manager = get_session_manager()
    success = manager.close_session(project_id)

    return {
        "project_id": project_id,
        "closed": success,
    }


# ============================================================================
# Server Factory
# ============================================================================


def create_server() -> FastMCP:
    """Create and return the configured MCP server instance."""
    return mcp
