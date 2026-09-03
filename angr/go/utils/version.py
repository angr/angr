from __future__ import annotations

import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from angr import Project

_GO_VERSION_RE = re.compile(rb"go1\.\d+(?:\.\d+)?(?:rc\d+|beta\d+)?")
_BUILDINFO_MAGIC = b"\xff Go buildinf:"


def go_minor_version(version: str) -> str:
    """``go1.22.5`` -> ``go1.22``."""
    m = re.match(r"(go\d+\.\d+)", version)
    return m.group(1) if m else version


def identify_go_version(project: Project) -> str | None:
    """
    The Go release a binary was built with (``go1.22.5``), from runtime.buildVersion, the build-info blob, or the
    first release marker in read-only data.
    """
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

    pclntab = getattr(obj, "gopclntab", None)
    if pclntab is not None and pclntab.go_version is not None:
        major, minor = pclntab.go_version
        return f"go{major}.{minor}"
    return None
