from __future__ import annotations

from fastmcp.exceptions import ToolError

from angr.errors import AngrError


class MCPAngrError(AngrError, ToolError):
    """
    Base exception for MCP angr server errors.

    Also a fastmcp ToolError: FastMCP masks the message of anything else, so a client would
    otherwise see a generic failure instead of the reason.
    """


class ProjectNotFoundError(MCPAngrError):
    """Raised when a project ID is not found."""


class CFGNotBuiltError(MCPAngrError):
    """Raised when CFG is required but not built."""


class FunctionNotFoundError(MCPAngrError):
    """Raised when a function cannot be found."""


class DecompilationError(MCPAngrError):
    """Raised when decompilation fails."""


class InvalidArgumentError(MCPAngrError, ValueError):
    """Raised when a tool is called with unusable arguments."""
