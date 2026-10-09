from __future__ import annotations

import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from angr import Project

# (oldest, newest) Go release (major, minor); newest is None when unbounded
type GoVersionRange = tuple[tuple[int, int], tuple[int, int] | None]

_GO_VERSION_RE = re.compile(rb"go1\.\d+(?:\.\d+)?(?:rc\d+|beta\d+)?")
_BUILDINFO_MAGIC = b"\xff Go buildinf:"


def go_minor_version(version: str) -> str:
    """``go1.22.5`` -> ``go1.22``."""
    m = re.match(r"(go\d+\.\d+)", version)
    return m.group(1) if m else version


def identify_go_version(project: Project) -> str | None:
    """
    The Go release a binary was built with (``go1.22.5``), from runtime.buildVersion, the build-info blob, or the
    first release marker in read-only data. Failing those, the oldest release that emits the binary's pclntab layout
    (``go1.16``), which is only a lower bound.
    """
    version = _exact_go_version(project)
    if version is not None:
        return version
    pclntab = project.loader.main_object.gopclntab
    if pclntab is not None and pclntab.go_version is not None:
        major, minor = pclntab.go_version
        return f"go{major}.{minor}"
    return None


def _exact_go_version(project: Project) -> str | None:
    obj = project.loader.main_object
    memory = project.loader.memory

    sym = project.loader.find_symbol("runtime.buildVersion")
    if sym is not None:
        try:
            ptr = memory.unpack_word(sym.rebased_addr, project.arch.bytes)
            length = memory.unpack_word(sym.rebased_addr + project.arch.bytes, project.arch.bytes)
            if 0 < length < 64:
                m = _GO_VERSION_RE.fullmatch(memory.load(ptr, length))
                if m:
                    return m.group(0).decode()
        except KeyError:
            pass

    for section in obj.sections:
        if section.name == ".go.buildinfo" and section.memsize:
            try:
                data = memory.load(section.vaddr, min(section.memsize, 0x1000))
            except KeyError:
                continue
            m = _GO_VERSION_RE.search(data)
            if m:
                return m.group(0).decode()

    for section in obj.sections:
        if section.name in (".rodata", ".rdata", "__rodata") and section.memsize:
            try:
                data = memory.load(section.vaddr, section.memsize)
            except KeyError:
                continue
            m = _GO_VERSION_RE.search(data)
            if m:
                return m.group(0).decode()
    return None


def parse_go_version(version: str) -> tuple[int, int] | None:
    """``go1.22.5`` -> ``(1, 22)``."""
    m = re.match(r"go(\d+)\.(\d+)", version)
    return (int(m.group(1)), int(m.group(2))) if m else None


# The newest release that emits each pclntab layout, keyed by the oldest one (cle's GoPclntab.go_version). The go1.20
# layout is still current, so it has no upper bound.
_PCLNTAB_LAYOUT_NEWEST: dict[tuple[int, int], tuple[int, int]] = {
    (1, 2): (1, 9),
    (1, 10): (1, 11),
    (1, 12): (1, 15),
    (1, 16): (1, 17),
    (1, 18): (1, 19),
}


def go_version_range(project: Project) -> GoVersionRange | None:
    """
    The (oldest, newest) Go releases (``(major, minor)``) the binary may have been built with. Both are the same when
    the exact release is known; otherwise they span the releases that emit its pclntab layout, and newest is None when
    that layout is still current. None if nothing identifies the release.
    """
    version = _exact_go_version(project)
    parsed = parse_go_version(version) if version is not None else None
    if parsed is not None:
        return parsed, parsed
    pclntab = project.loader.main_object.gopclntab
    if pclntab is not None and pclntab.go_version is not None:
        oldest = pclntab.go_version
        return oldest, _PCLNTAB_LAYOUT_NEWEST.get(oldest)
    return None


# cle's description of the target OS -> GOOS. The gc linker sets EI_OSABI only for the BSDs; every other ELF target
# (linux, android, dragonfly, illumos, solaris) is indistinguishable here.
_OS_TO_GOOS = {
    "windows": "windows",
    "macos": "darwin",
    "UNIX - FreeBSD": "freebsd",
    "UNIX - NetBSD": "netbsd",
    "UNIX - OpenBSD": "openbsd",
}


def identify_goos(project: Project) -> str | None:
    """The binary's GOOS, when its container format tells; None otherwise."""
    return _OS_TO_GOOS.get(project.loader.main_object.os)
