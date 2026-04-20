from __future__ import annotations

import pytest

from angr.mcp import __main__ as mcp_main


class DummyMCP:
    """Test double for the MCP server object."""

    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    def run(self, **kwargs: object) -> None:
        self.calls.append(kwargs)


@pytest.mark.parametrize(
    ("argv", "expected"),
    [
        ([], {"transport": "stdio"}),
        (
            ["--transport", "sse", "--host", "0.0.0.0", "--port", "8123"],
            {"transport": "sse", "host": "0.0.0.0", "port": 8123},
        ),
        (
            ["--transport", "http", "--host", "0.0.0.0", "--port", "8123", "--path", "/custom"],
            {"transport": "http", "host": "0.0.0.0", "port": 8123, "path": "/custom"},
        ),
    ],
)
def test_main_dispatches_transport(monkeypatch, argv: list[str], expected: dict[str, object]) -> None:
    dummy_mcp = DummyMCP()
    monkeypatch.setattr(mcp_main, "mcp", dummy_mcp)

    mcp_main.main(argv)

    assert dummy_mcp.calls == [expected]


def test_http_path_must_be_absolute(monkeypatch) -> None:
    dummy_mcp = DummyMCP()
    monkeypatch.setattr(mcp_main, "mcp", dummy_mcp)

    with pytest.raises(SystemExit) as exc_info:
        mcp_main.main(["--transport", "http", "--path", "mcp"])

    assert exc_info.value.code == 2
    assert not dummy_mcp.calls
