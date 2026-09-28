"""
Where PUSHAN's diagnostic artifacts go.

Every SVG, pickle and counter the VM-deobfuscation pipeline writes goes through
:class:`ArtifactStore` so the location is decided once, by the caller, instead of
being derived from the analyzed binary's directory (which pollutes shared corpora)
or from the process CWD at each individual call site (which makes parallel runs
overwrite each other).

Resolution order: explicit ``artifacts_dir`` argument, then ``$PUSHAN_ARTIFACTS_DIR``,
then the current working directory.

``last_decomp_result.c`` is deliberately NOT routed through here: the evaluation
harness copies it out of the CWD it launched each target in.
"""

from __future__ import annotations

import os
from pathlib import Path

ENV_VAR = "PUSHAN_ARTIFACTS_DIR"

_PROJECT_ATTR = "_pushan_artifact_store"


def resolve_artifacts_dir(artifacts_dir: str | os.PathLike | None = None) -> Path:
    """
    Explicit argument wins, then $PUSHAN_ARTIFACTS_DIR, then the CWD.
    """
    if artifacts_dir is None:
        artifacts_dir = os.environ.get(ENV_VAR) or None
    if artifacts_dir is None:
        return Path.cwd().resolve()
    return Path(artifacts_dir).expanduser().resolve()


class ArtifactStore:
    """
    A directory the pipeline may write diagnostics into. ``name`` may contain "/" to
    land in a subdirectory; parent directories are created on demand.
    """

    __slots__ = ("dir",)

    def __init__(self, artifacts_dir: str | os.PathLike | None = None):
        self.dir = resolve_artifacts_dir(artifacts_dir)
        self.dir.mkdir(parents=True, exist_ok=True)

    def path(self, name: str | os.PathLike) -> Path:
        p = self.dir / name
        if p.parent != self.dir:
            p.parent.mkdir(parents=True, exist_ok=True)
        return p

    def open(self, name: str | os.PathLike, mode: str = "w", **kwargs):
        return self.path(name).open(mode, **kwargs)

    def __repr__(self):
        return f"<ArtifactStore {self.dir}>"


def store_for(project, artifacts_dir: str | os.PathLike | None = None) -> ArtifactStore:
    """
    The store for ``project``, created on first use. An explicit ``artifacts_dir``
    re-points the project at that directory; analyses driven by a caller that already
    resolved one pass it down, so the whole run shares a single location.
    """
    store = getattr(project, _PROJECT_ATTR, None)
    if store is None or artifacts_dir is not None:
        store = ArtifactStore(artifacts_dir)
        setattr(project, _PROJECT_ATTR, store)
    return store
