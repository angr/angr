from __future__ import annotations

import pytest

from angr.mcp.session import (
    ProjectSession,
    SessionManager,
    get_session_manager,
)


class TestProjectSession:
    """Tests for the ProjectSession dataclass."""

    def test_has_cfg_false_initially(self, loaded_session):
        """Test that has_cfg is False when CFG not built."""
        assert loaded_session.has_cfg is False

    def test_has_cfg_true_after_building(self, loaded_session_with_cfg):
        """Test that has_cfg is True after CFG is built."""
        assert loaded_session_with_cfg.has_cfg is True

    def test_session_attributes(self, loaded_session, binary_path):
        """Test that session has correct attributes."""
        assert loaded_session.project_id is not None
        assert len(loaded_session.project_id) == 8
        # binary_path is resolved to absolute path
        assert loaded_session.binary_path.endswith("1after909")
        assert loaded_session.project is not None
        assert loaded_session.cfg is None


class TestSessionManager:
    """Tests for the SessionManager class."""

    def test_create_session(self, session_manager, binary_path):
        """Test creating a new session."""
        session = session_manager.create_session(binary_path)

        assert session.project_id is not None
        assert session.binary_path.endswith("1after909")
        assert session.project.arch.name == "AMD64"

    def test_create_session_with_options(self, session_manager, binary_path):
        """Test creating a session with custom options."""
        session = session_manager.create_session(
            binary_path,
            auto_load_libs=False,
        )

        assert session.project is not None
        # Verify main binary is loaded
        assert session.project.loader.main_object is not None
        assert session.project.loader.main_object.binary_basename == "1after909"

    def test_create_session_file_not_found(self, session_manager):
        """Test that creating session with invalid path raises error."""
        with pytest.raises(FileNotFoundError):
            session_manager.create_session("/nonexistent/binary")

    def test_get_session(self, session_manager, binary_path):
        """Test retrieving an existing session."""
        created = session_manager.create_session(binary_path)
        retrieved = session_manager.get_session(created.project_id)

        assert retrieved is created
        assert retrieved.project_id == created.project_id

    def test_get_session_not_found(self, session_manager):
        """Test that getting nonexistent session raises error."""
        with pytest.raises(KeyError) as exc_info:
            session_manager.get_session("nonexistent")

        assert "nonexistent" in str(exc_info.value)

    def test_list_sessions_empty(self, session_manager):
        """Test listing sessions when none exist."""
        sessions = session_manager.list_sessions()
        assert sessions == []

    def test_list_sessions(self, session_manager, binary_path):
        """Test listing active sessions."""
        session = session_manager.create_session(binary_path)
        sessions = session_manager.list_sessions()

        assert len(sessions) == 1
        assert sessions[0]["project_id"] == session.project_id
        assert sessions[0]["arch"] == "AMD64"
        assert sessions[0]["has_cfg"] is False

    def test_list_sessions_multiple(self, session_manager, binary_path, i386_binary_path):
        """Test listing multiple sessions."""
        session1 = session_manager.create_session(binary_path)
        session2 = session_manager.create_session(i386_binary_path)

        sessions = session_manager.list_sessions()
        assert len(sessions) == 2

        project_ids = {s["project_id"] for s in sessions}
        assert session1.project_id in project_ids
        assert session2.project_id in project_ids

    def test_close_session(self, session_manager, binary_path):
        """Test closing a session."""
        session = session_manager.create_session(binary_path)
        project_id = session.project_id

        result = session_manager.close_session(project_id)
        assert result is True

        # Verify session is gone
        with pytest.raises(KeyError):
            session_manager.get_session(project_id)

    def test_close_session_not_found(self, session_manager):
        """Test closing nonexistent session returns False."""
        result = session_manager.close_session("nonexistent")
        assert result is False

    def test_unique_project_ids(self, session_manager, binary_path):
        """Test that each session gets a unique project_id."""
        sessions = [session_manager.create_session(binary_path) for _ in range(5)]
        project_ids = [s.project_id for s in sessions]

        assert len(project_ids) == len(set(project_ids))


class TestGlobalSessionManager:
    """Tests for the global session manager singleton."""

    def test_get_session_manager_returns_same_instance(self):
        """Test that get_session_manager returns the same instance."""
        manager1 = get_session_manager()
        manager2 = get_session_manager()

        assert manager1 is manager2

    def test_global_manager_persistence(self, global_session_manager, binary_path):
        """Test that sessions persist in the global manager."""
        session = global_session_manager.create_session(binary_path)

        # Get manager again and verify session exists
        manager = get_session_manager()
        retrieved = manager.get_session(session.project_id)

        assert retrieved.project_id == session.project_id

        # Cleanup
        manager.close_session(session.project_id)
