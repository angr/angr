from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from angr import Project
    from angr.sim_type import SimType


def go_type_name_at(project: Project, addr: int) -> str | None:
    """
    The Go spelling of the runtime type descriptor at ``addr`` (``main.node``, ``*main.node``, ``[]int``), from the
    parsed descriptor table when available, otherwise from DWARF or a ``type:...`` symbol.
    """
    go_types = getattr(project.kb, "go_types", None)
    if go_types is not None:
        name = go_types.name_at(addr)
        if name is not None:
            return name
    go_signatures = getattr(project.kb, "go_signatures", None)
    if go_signatures is not None:
        go_signatures.load_sources()
        name = go_signatures.type_name_at(addr)
        if name is not None:
            return name
    sym = project.loader.find_symbol(addr)
    if sym is not None and sym.name.startswith("type:") and not sym.name.startswith("type:."):
        return sym.name[len("type:") :]
    return None


def go_type_at(project: Project, addr: int) -> SimType | None:
    """The SimType of the runtime type descriptor at ``addr``, or None when it is not a known descriptor."""
    name = go_type_name_at(project, addr)
    if name is None:
        return None
    try:
        return project.kb.go_signatures.type(name)
    except Exception:  # pylint:disable=broad-exception-caught
        return None
