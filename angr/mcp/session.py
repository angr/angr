from __future__ import annotations

"""Session management for angr MCP server."""

import logging
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    import angr
    from angr.knowledge_plugins.cfg import CFGModel

l = logging.getLogger(__name__)


@dataclass
class ProjectSession:
    """Represents a loaded angr project with its associated analyses."""

    project_id: str
    project: angr.Project
    binary_path: str
    cfg: CFGModel | None = None

    @property
    def has_cfg(self) -> bool:
        """Check if CFG has been built for this project."""
        return self.cfg is not None


class SessionManager:
    """
    Manages multiple angr project sessions.

    This class maintains state across MCP tool invocations, allowing
    projects to persist between calls.
    """

    def __init__(self) -> None:
        self._sessions: dict[str, ProjectSession] = {}

    def create_session(self, binary_path: str, **kwargs: Any) -> ProjectSession:
        """
        Load a binary and create a new project session.

        :param binary_path: Path to the binary to analyze
        :param kwargs: Additional arguments passed to angr.Project
        :return: The created ProjectSession with unique ID
        """
        import angr

        # Validate path
        path = Path(binary_path)
        if not path.exists():
            raise FileNotFoundError(f"Binary not found: {binary_path}")

        # Set default options
        if "auto_load_libs" not in kwargs:
            kwargs["auto_load_libs"] = False

        # Create project
        project = angr.Project(str(path), **kwargs)

        # Generate unique ID
        project_id = str(uuid.uuid4())[:8]

        session = ProjectSession(
            project_id=project_id,
            project=project,
            binary_path=str(path.resolve()),
        )

        self._sessions[project_id] = session
        l.info("Created session %s for %s", project_id, binary_path)

        return session

    def get_session(self, project_id: str) -> ProjectSession:
        """
        Get an existing session by ID.

        :param project_id: The project ID to look up
        :return: The ProjectSession
        :raises KeyError: If no project with that ID exists
        """
        if project_id not in self._sessions:
            available = list(self._sessions.keys())
            raise KeyError(f"No project with ID '{project_id}' found. " f"Available: {available}")
        return self._sessions[project_id]

    def list_sessions(self) -> list[dict[str, Any]]:
        """
        List all active sessions.

        :return: List of session metadata dictionaries
        """
        return [
            {
                "project_id": s.project_id,
                "binary_path": s.binary_path,
                "has_cfg": s.has_cfg,
                "arch": s.project.arch.name,
            }
            for s in self._sessions.values()
        ]

    def close_session(self, project_id: str) -> bool:
        """
        Close and remove a session.

        :param project_id: The project ID to close
        :return: True if closed, False if not found
        """
        if project_id in self._sessions:
            del self._sessions[project_id]
            l.info("Closed session %s", project_id)
            return True
        return False


# Global session manager instance
_session_manager: SessionManager | None = None


def get_session_manager() -> SessionManager:
    """Get or create the global session manager."""
    global _session_manager
    if _session_manager is None:
        _session_manager = SessionManager()
    return _session_manager
