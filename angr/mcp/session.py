"""Session management for angr MCP server."""

from __future__ import annotations

import hashlib
import logging
import threading
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

import archinfo
import cle

import angr
from angr.enums import Flavors

from .errors import InvalidArgumentError

if TYPE_CHECKING:
    from collections.abc import Iterator

    from angr.knowledge_plugins.cfg import CFGModel

l = logging.getLogger(__name__)

AVAILABLE_FLAVORS: tuple[str, ...] = tuple(str(f) for f in Flavors)


def parse_flavor(flavor: str) -> str:
    """Validate a decompilation flavor name, naming the valid ones on failure."""
    try:
        return str(Flavors(flavor))
    except ValueError as e:
        raise InvalidArgumentError(
            f"Unknown decompilation flavor {flavor!r}. Valid flavors: {', '.join(AVAILABLE_FLAVORS)}."
        ) from e


SUPPORTED_BACKENDS: tuple[str, ...] = ("blob",)


def parse_address_option(name: str, value: str | int | None) -> int | None:
    """Parse an optional hex-or-decimal address option, naming the option on failure."""
    if value is None:
        return None
    try:
        return int(value, 0) if isinstance(value, str) else int(value)
    except ValueError as e:
        raise InvalidArgumentError(f"{name} must be a hexadecimal (0x...) or decimal address, got {value!r}.") from e


def parse_arch_option(arch: str | None) -> archinfo.Arch | None:
    """Resolve an archinfo identifier such as "x86_64", "aarch64", "armel", or "mips32"."""
    if arch is None:
        return None
    try:
        return archinfo.arch_from_id(arch)
    except (archinfo.ArchError, archinfo.ArchNotFound) as e:
        names = sorted({a.name.lower() for a in archinfo.all_arches})
        raise InvalidArgumentError(f"Unknown architecture {arch!r}. Known names include: {', '.join(names)}.") from e


def build_main_opts(
    *,
    arch: str | None = None,
    backend: str | None = None,
    base_address: str | int | None = None,
    entry_point: str | int | None = None,
) -> dict[str, Any]:
    """
    Translate load_binary's optional loader inputs into CLE main_opts.

    ``arch`` selects the slice of a universal Mach-O or overrides a headered file. ``backend="blob"``
    with ``arch`` loads a headerless raw binary at ``base_address`` with ``entry_point``.
    """
    if backend is not None and backend not in SUPPORTED_BACKENDS:
        raise InvalidArgumentError(
            f"Unsupported backend {backend!r}. Supported backends: {', '.join(SUPPORTED_BACKENDS)}."
        )
    main_opts: dict[str, Any] = {}
    parsed_arch = parse_arch_option(arch)
    if backend == "blob" and parsed_arch is None:
        raise InvalidArgumentError("backend 'blob' requires arch: a headerless binary has no architecture header.")
    if parsed_arch is not None:
        main_opts["arch"] = parsed_arch
    if backend is not None:
        main_opts["backend"] = backend
    base = parse_address_option("base_address", base_address)
    if base is not None:
        main_opts["base_addr"] = base
    entry = parse_address_option("entry_point", entry_point)
    if entry is not None:
        main_opts["entry_point"] = entry
    return main_opts


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def reject_dos_executable(path: Path) -> None:
    """16-bit DOS MZ images share PE's magic but have no lifter; report that instead of a loader crash."""
    with path.open("rb") as stream:
        if stream.read(2) != b"MZ":
            return
        stream.seek(0)
        if cle.PE.is_compatible(stream):
            return
    raise InvalidArgumentError(
        "16-bit DOS executables are not supported: the file has an MZ header without a PE header, and angr has "
        "no 16-bit x86 lifter."
    )


@dataclass
class ProjectSession:
    """Represents a loaded angr project with its associated analyses."""

    project_id: str
    project: angr.Project
    binary_path: str
    cfg: CFGModel | None = None
    # SHA-256 of the loaded file, so a client on another filesystem view can verify identity
    sha256: str = ""
    # project-wide decompilation flavor; decompile_function may override it per call
    flavor: str = Flavors.DEFAULT_FLAVOR
    lock: threading.RLock = field(default_factory=threading.RLock, repr=False, compare=False)

    def set_flavor(self, flavor: str) -> str:
        """Set the project-wide decompilation flavor and return the previous one."""
        previous = self.flavor
        self.flavor = parse_flavor(flavor)
        return previous

    @property
    def has_cfg(self) -> bool:
        """Check if CFG has been built for this project."""
        return self.cfg is not None

    @contextmanager
    def exclusive(self) -> Iterator[ProjectSession]:
        """
        Serialize access to this project.

        FastMCP runs synchronous tools on worker threads, so two calls can reach the same Project
        and KnowledgeBase at once. Neither is thread-safe, and the decompilation and variable caches
        spill to LMDB, where a concurrent eviction and reload can hand back a half-imported object.
        Read-only tools are not exempt: a read racing an eviction is exactly that hazard.
        """
        with self.lock:
            yield self


class SessionManager:
    """
    Manages multiple angr project sessions.

    This class maintains state across MCP tool invocations, allowing
    projects to persist between calls.
    """

    def __init__(self) -> None:
        self._sessions: dict[str, ProjectSession] = {}
        self._lock = threading.Lock()

    def create_session(self, binary_path: str, **kwargs: Any) -> ProjectSession:
        """
        Load a binary and create a new project session.

        :param binary_path: Path to the binary to analyze
        :param kwargs: Additional arguments passed to angr.Project
        :return: The created ProjectSession with unique ID
        """

        # Validate path
        path = Path(binary_path)
        if not path.exists():
            raise FileNotFoundError(f"Binary not found: {binary_path}")

        # Set default options
        if "auto_load_libs" not in kwargs:
            kwargs["auto_load_libs"] = False
        if not kwargs.get("main_opts", {}).get("backend"):
            reject_dos_executable(path)

        # Create project
        try:
            project = angr.Project(str(path), **kwargs)
        except KeyError as e:
            # Universal2 reports a requested slice the container lacks this way
            raise InvalidArgumentError(str(e).strip("'\"")) from e
        except cle.CLECompatibilityError as e:
            raise InvalidArgumentError(f"angr cannot load {binary_path}: {e}") from e

        # Generate unique ID
        project_id = str(uuid.uuid4())[:8]

        session = ProjectSession(
            project_id=project_id,
            project=project,
            binary_path=str(path.resolve()),
            sha256=_file_sha256(path),
        )

        with self._lock:
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
        with self._lock:
            if project_id not in self._sessions:
                available = list(self._sessions.keys())
                raise KeyError(f"No project with ID '{project_id}' found. Available: {available}")
            return self._sessions[project_id]

    def list_sessions(self) -> list[dict[str, Any]]:
        """
        List all active sessions.

        :return: List of session metadata dictionaries
        """
        with self._lock:
            sessions = list(self._sessions.values())
        return [
            {
                "project_id": s.project_id,
                "binary_path": s.binary_path,
                "has_cfg": s.has_cfg,
                "arch": s.project.arch.name,
                "sha256": s.sha256,
                "flavor": s.flavor,
            }
            for s in sessions
        ]

    def close_session(self, project_id: str) -> bool:
        """
        Close and remove a session.

        :param project_id: The project ID to close
        :return: True if closed, False if not found
        """
        with self._lock:
            if project_id not in self._sessions:
                return False
            del self._sessions[project_id]
        l.info("Closed session %s", project_id)
        return True


# Global session manager instance
_session_manager: SessionManager | None = None


def get_session_manager() -> SessionManager:
    """Get or create the global session manager."""
    global _session_manager  # pylint: disable=global-statement

    if _session_manager is None:
        _session_manager = SessionManager()
    return _session_manager
