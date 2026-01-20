from __future__ import annotations

import os
import pytest

import angr
from angr.mcp.session import SessionManager, get_session_manager


# Path to test binaries
BIN_LOCATION = os.path.join(
    os.path.dirname(os.path.realpath(__file__)), "..", "..", "..", "binaries"
)

# Test binary paths
X86_64_BINARY = os.path.join(BIN_LOCATION, "tests", "x86_64", "1after909")
I386_BINARY = os.path.join(BIN_LOCATION, "tests", "i386", "fauxware")


@pytest.fixture
def binary_path() -> str:
    """Return path to the x86_64 test binary."""
    if not os.path.exists(X86_64_BINARY):
        pytest.skip(f"Test binary not found: {X86_64_BINARY}")
    return X86_64_BINARY


@pytest.fixture
def i386_binary_path() -> str:
    """Return path to the i386 test binary."""
    if not os.path.exists(I386_BINARY):
        pytest.skip(f"Test binary not found: {I386_BINARY}")
    return I386_BINARY


@pytest.fixture
def session_manager() -> SessionManager:
    """Create a fresh SessionManager for each test."""
    return SessionManager()


@pytest.fixture
def global_session_manager() -> SessionManager:
    """Get the global session manager, clearing any existing sessions."""
    manager = get_session_manager()
    # Clear any existing sessions
    for project_id in list(manager._sessions.keys()):
        manager.close_session(project_id)
    return manager


@pytest.fixture
def angr_project(binary_path: str) -> angr.Project:
    """Create an angr Project for testing."""
    return angr.Project(binary_path, auto_load_libs=False)


@pytest.fixture
def angr_project_with_cfg(angr_project: angr.Project) -> angr.Project:
    """Create an angr Project with CFG already built."""
    angr_project.analyses.CFGFast(normalize=True, data_references=True)
    return angr_project


@pytest.fixture
def loaded_session(session_manager: SessionManager, binary_path: str):
    """Create a session with a loaded binary."""
    return session_manager.create_session(binary_path)


@pytest.fixture
def loaded_session_with_cfg(loaded_session):
    """Create a session with CFG built."""
    proj = loaded_session.project
    cfg = proj.analyses.CFGFast(normalize=True, data_references=True)
    loaded_session.cfg = cfg.model
    return loaded_session
