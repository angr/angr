from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import TYPE_CHECKING

from angr.go.analyses.dwarf_signatures import read_go_dwarf_signatures
from angr.go.signature import GoFuncSignature, GoNamedType, GoSignatureSet, GoVariable
from angr.go.sim_type import GoSimTypeFunction, GoSimTypeTuple
from angr.go.type_parser import GoTypeParser
from angr.go.utils.version import go_minor_version, identify_go_version
from angr.knowledge_plugins.plugin import KnowledgeBasePlugin
from angr.utils.go_runtime import normalize_go_func_name

if TYPE_CHECKING:
    from angr.sim_type import SimType

l = logging.getLogger(__name__)

_DB_CACHE: dict[str, GoSignatureSet | None] = {}

# assembly runtime functions whose Go declaration lives under a go:linkname alias
_LINKNAME_ALIASES = {
    "runtime.cmpstring": "internal/bytealg.abigen_runtime_cmpstring",
    "runtime.memequal": "internal/bytealg.abigen_runtime_memequal",
    "runtime.memequal_varlen": "internal/bytealg.abigen_runtime_memequal_varlen",
}


def available_signature_dbs() -> dict[str, Path]:
    """Installed stdlib signature databases, keyed by minor version (``go1.22``)."""
    try:
        import angr_data  # pylint:disable=import-outside-toplevel
    except ImportError:
        return {}
    sigdb = Path(angr_data.get_path("go", "sigdb"))
    if not sigdb.is_dir():
        return {}
    return {p.stem: p for p in sigdb.glob("go1.*.json")}


def load_signature_db(go_version: str | None) -> GoSignatureSet | None:
    """
    The stdlib signature database for ``go_version``, falling back to the closest installed minor version.
    """
    dbs = available_signature_dbs()
    if not dbs:
        return None
    wanted = go_minor_version(go_version) if go_version else None

    def minor(v: str) -> int:
        m = re.match(r"go1\.(\d+)", v)
        return int(m.group(1)) if m else -1

    if wanted in dbs:
        chosen = wanted
    else:
        # closest version, preferring an older one (signatures only grow over time)
        target = minor(wanted) if wanted else max(minor(v) for v in dbs)
        older = [v for v in dbs if minor(v) <= target]
        chosen = max(older, key=minor) if older else min(dbs, key=minor)
        if wanted:
            l.info("No Go signature database for %s; using %s.", wanted, chosen)

    if chosen not in _DB_CACHE:
        with open(dbs[chosen], encoding="utf-8") as f:
            _DB_CACHE[chosen] = GoSignatureSet.from_json(json.load(f))
    return _DB_CACHE[chosen]


class GoSignatures(KnowledgeBasePlugin):
    """
    Go function signatures and named types known for this binary, merged from every source (external tools, DWARF,
    the binary's runtime type descriptors, the stdlib database, in that priority) and turned into Go SimTypes on
    demand.
    """

    def __init__(self, kb):
        super().__init__(kb)
        self.go_version: str | None = None
        self._sources: list[GoSignatureSet] = []
        self._stdlib_loaded = False
        self._parser: GoTypeParser | None = None
        self._prototypes: dict[str, GoSimTypeFunction | None] = {}

    #
    # Sources
    #

    def add_source(self, sigs: GoSignatureSet, priority: int | None = None) -> None:
        """Register a signature set; earlier sources win. ``priority=0`` puts it in front."""
        if priority is None:
            self._sources.append(sigs)
        else:
            self._sources.insert(priority, sigs)
        self._prototypes.clear()
        self._parser = None

    def load_sources(self, go_version: str | None = None) -> bool:
        """
        Load the binary's own DWARF signatures (when present), its runtime type descriptors and the stdlib database
        for its Go version. Runs once.
        """
        if self._stdlib_loaded:
            return bool(self._sources)
        self._stdlib_loaded = True
        project = self._kb._project
        self.go_version = go_version or self.go_version or (identify_go_version(project) if project else None)

        if project is not None:
            try:
                dwarf = read_go_dwarf_signatures(project)
            except Exception as e:  # pylint:disable=broad-exception-caught
                l.warning("Reading Go DWARF signatures failed: %s", e)
                dwarf = None
            if dwarf is not None and (dwarf.functions or dwarf.types):
                self._sources.append(dwarf)
            # the descriptors are the truth about this binary's layouts; DWARF stays first for its parameter names
            descriptors = self._kb.go_types.types
            if descriptors.types:
                self._sources.append(descriptors)
                if self.go_version is None:
                    self.go_version = descriptors.go_version

        db = load_signature_db(self.go_version)
        if db is None:
            l.warning("No Go signature database is installed (angr-data).")
        else:
            self._sources.append(db)
        self._prototypes.clear()
        self._parser = None
        return bool(self._sources)

    load_stdlib = load_sources

    #
    # Lookup
    #

    def signature(self, name: str) -> GoFuncSignature | None:
        name = normalize_go_func_name(name)
        empty = None
        for lookup in (name, _LINKNAME_ALIASES.get(name)):
            if lookup is None:
                continue
            for src in self._sources:
                sig = src.functions.get(lookup)
                if sig is None:
                    continue
                if sig.params or sig.results or sig.recv:
                    return sig
                # assembly functions have a DWARF subprogram without parameters; keep looking for a typed one
                empty = empty or sig
        return empty

    def variable_at(self, addr: int) -> GoVariable | None:
        for src in self._sources:
            for var in src.variables.values():
                if var.addr == addr:
                    return var
        return None

    def named_type(self, name: str) -> GoNamedType | None:
        first = None
        for src in self._sources:
            ty = src.types.get(name)
            if ty is None:
                continue
            # DWARF describes interfaces without their methods; prefer a source that has them
            if ty.kind != "interface" or ty.methods:
                return ty
            if first is None:
                first = ty
        return first

    def type_name_at(self, addr: int) -> str | None:
        """The name of the type whose runtime descriptor is at ``addr``, when a source (DWARF) recorded it."""
        for src in self._sources:
            name = src.runtime_types.get(addr)
            if name is not None:
                return name
        return None

    @property
    def parser(self) -> GoTypeParser:
        if self._parser is None:
            self._parser = GoTypeParser(self._kb._project.arch, self.named_type)
        return self._parser

    def type(self, type_str: str) -> SimType:
        return self.parser.parse(type_str)

    @staticmethod
    def _implicit_signature(name: str) -> GoFuncSignature | None:
        """Entry points and package initializers never take or return anything."""
        if name == "main.main" or re.search(r"\.init(?:\.\d+)?$", name):
            return GoFuncSignature(name)
        return None

    def prototype(self, name: str) -> GoSimTypeFunction | None:
        """The function type of ``name`` (receiver first), or None when the signature is unknown."""
        name = normalize_go_func_name(name)
        if name in self._prototypes:
            return self._prototypes[name]
        sig = self.signature(name) or self._implicit_signature(name)
        proto = self._build_prototype(sig) if sig is not None else None
        self._prototypes[name] = proto
        return proto

    def _build_prototype(self, sig: GoFuncSignature) -> GoSimTypeFunction:
        parser = self.parser
        params = sig.all_params
        args = [parser.parse(p.type_str) for p in params]
        results = [parser.parse(r.type_str) for r in sig.results]
        if not results:
            returnty = None
        elif len(results) == 1:
            returnty = results[0]
        else:
            returnty = GoSimTypeTuple(results, [r.name for r in sig.results])
        arch = self._kb._project.arch
        return GoSimTypeFunction(args, returnty, arg_names=[p.name for p in params]).with_arch(arch)

    def copy(self):
        o = GoSignatures(self._kb)
        o.go_version = self.go_version
        o._sources = list(self._sources)
        o._stdlib_loaded = self._stdlib_loaded
        return o


KnowledgeBasePlugin.register_default("go_signatures", GoSignatures)
