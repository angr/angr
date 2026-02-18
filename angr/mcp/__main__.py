from __future__ import annotations

"""Entry point for running the angr MCP server."""

import argparse
import logging
import sys


def main() -> None:
    """Entry point for running the angr MCP server."""
    parser = argparse.ArgumentParser(description="angr MCP Server - Binary analysis via Model Context Protocol")
    parser.add_argument(
        "--transport",
        choices=["stdio", "sse"],
        default="stdio",
        help="Transport mechanism (default: stdio)",
    )
    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default="WARNING",
        help="Logging level (default: WARNING)",
    )
    parser.add_argument(
        "--host",
        default="localhost",
        help="Host for SSE transport (default: localhost)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8000,
        help="Port for SSE transport (default: 8000)",
    )

    args = parser.parse_args()

    # Configure logging
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        stream=sys.stderr,
    )

    # Suppress verbose angr logging unless DEBUG
    if args.log_level != "DEBUG":
        logging.getLogger("angr").setLevel(logging.ERROR)
        logging.getLogger("cle").setLevel(logging.ERROR)
        logging.getLogger("pyvex").setLevel(logging.ERROR)
        logging.getLogger("claripy").setLevel(logging.ERROR)
        logging.getLogger("archinfo").setLevel(logging.ERROR)

    from .server import mcp

    if args.transport == "stdio":
        mcp.run(transport="stdio")
    elif args.transport == "sse":
        mcp.run(transport="sse", host=args.host, port=args.port)


if __name__ == "__main__":
    main()
