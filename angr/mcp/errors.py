from __future__ import annotations

from angr.errors import AngrError


class MCPAngrError(AngrError):
    """Base exception for MCP angr server errors."""


class ProjectNotFoundError(MCPAngrError):
    """Raised when a project ID is not found."""


class CFGNotBuiltError(MCPAngrError):
    """Raised when CFG is required but not built."""


class FunctionNotFoundError(MCPAngrError):
    """Raised when a function cannot be found."""


class DecompilationError(MCPAngrError):
    """Raised when decompilation fails."""
