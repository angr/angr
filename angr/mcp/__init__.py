from __future__ import annotations

"""
angr MCP Server - Model Context Protocol interface for angr binary analysis.

This module provides an MCP server that exposes angr's binary analysis
capabilities through standardized tools accessible by LLM applications.

Usage:
    # Run as module with stdio transport (for Claude Desktop, etc.)
    python -m angr.mcp

    # Run with SSE transport
    python -m angr.mcp --transport sse --port 8080

    # Programmatic usage
    from angr.mcp import create_server
    server = create_server()
    server.run()

Available Tools:
    - load_binary: Load a binary file for analysis
    - get_cfg: Build the control flow graph
    - list_functions: List discovered functions
    - get_function_info: Get detailed function information
    - decompile_function: Decompile to pseudocode
    - get_xrefs: Get cross-references
    - get_strings: Extract strings from binary
    - get_imports: List imported symbols
    - get_exports: List exported symbols
    - get_basic_blocks: Get basic blocks with disassembly
    - get_callgraph: Get function call graph
    - find_functions_by_pattern: Search functions by name
    - list_projects: List active analysis sessions
    - close_project: Close a project session
"""

from .exceptions import (
    CFGNotBuiltError,
    DecompilationError,
    FunctionNotFoundError,
    MCPAngrError,
    ProjectNotFoundError,
)
from .server import create_server, mcp
from .session import ProjectSession, SessionManager, get_session_manager

__all__ = [
    # Server
    "mcp",
    "create_server",
    # Session management
    "SessionManager",
    "ProjectSession",
    "get_session_manager",
    # Exceptions
    "MCPAngrError",
    "ProjectNotFoundError",
    "CFGNotBuiltError",
    "FunctionNotFoundError",
    "DecompilationError",
]
