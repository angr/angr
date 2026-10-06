from __future__ import annotations

import contextlib
import dataclasses
import json
import logging
import re
from pathlib import Path
from typing import TYPE_CHECKING

import angr_data

from angr.go.analyses.dwarf_signatures import _goarch, read_go_dwarf_signatures
from angr.go.signature import GoFuncSignature, GoNamedType, GoParam, GoSignatureSet, GoVariable
from angr.go.sim_type import GoSimType, GoSimTypeFunction, GoSimTypeSlice, GoSimTypeTuple, go_type_repr
from angr.go.type_parser import GoTypeParser
from angr.go.utils.version import go_minor_version, identify_go_version
from angr.knowledge_plugins.plugin import KnowledgeBasePlugin
from angr.sim_type import SimTypeBottom
from angr.utils.go_runtime import normalize_go_func_name

if TYPE_CHECKING:
    from collections.abc import Iterator

    from angr.knowledge_plugins.functions.function import Function
    from angr.sim_type import SimType

l = logging.getLogger(__name__)

_DB_CACHE: dict[str, GoSignatureSet | None] = {}

# assembly runtime functions whose Go declaration lives under a go:linkname alias
_LINKNAME_ALIASES = {
    "runtime.cmpstring": "internal/bytealg.abigen_runtime_cmpstring",
    "runtime.memequal": "internal/bytealg.abigen_runtime_memequal",
    "runtime.memequal_varlen": "internal/bytealg.abigen_runtime_memequal_varlen",
}


def _words(d) -> dict[int, tuple[str, int]]:
    """Normalize a word table that may have been through JSON (string keys, list values)."""
    return {int(k): (str(v[0]), int(v[1])) for k, v in (d or {}).items()}


def _groups(d) -> dict[int, tuple[int, str | None]]:
    """Normalize a group table (word -> (words spanned, type or None)) that may have been through JSON."""
    return {int(k): (int(v[0]), None if v[1] is None else str(v[1])) for k, v in (d or {}).items()}


def placeholder_group(words: int) -> str:
    """The spelling of ``words`` result words read together that nobody typed: a struct, so that it still travels in
    result registers (an array would go through memory under ABIInternal)."""
    return "struct { " + "; ".join(f"W{i} uintptr" for i in range(words)) + " }"


def is_placeholder_type(type_str: str) -> bool:
    """``uintptr`` or a word group nobody typed (``struct { W0 uintptr; W1 uintptr }``, ``[]uintptr``)."""
    return type_str in ("uintptr", "[]uintptr") or type_str.startswith("struct { W0 uintptr")


class GoInferredSignature(dict):
    """
    What the decompiler inferred about a function nobody names: parameter types from the callees its parameters
    reach, and result types from its own return statements (``results``, word -> (type, words spanned)) and from how
    callers use the result registers (``caller_results``). ``groups`` (word -> (words spanned, type or None)) are
    caller-side groupings of result words read as one value, typed when the shape of the reads says what they are
    (an interface pair), else kept together as a placeholder. Word indices count ABIInternal result registers. A
    plain dict underneath so records survive JSON and pickling between the processes of a sweep.
    """

    def __init__(self, params=None, results=None, caller_results=None, groups=None):
        super().__init__(
            params=list(params) if params else None, results={}, caller_results={}, groups={}, result_words=0
        )
        self.merge(params=None, results=results, caller_results=caller_results, groups=groups)

    @property
    def params(self) -> list[str] | None:
        return self["params"]

    @property
    def results(self) -> dict[int, tuple[str, int]]:
        return self["results"]

    @property
    def caller_results(self) -> dict[int, tuple[str, int]]:
        return self["caller_results"]

    @property
    def groups(self) -> dict[int, tuple[int, str | None]]:
        return self.setdefault("groups", {})

    @property
    def result_words(self) -> int:
        """How many result registers callers read after a call, typed or not."""
        return self.get("result_words", 0)

    @property
    def has_results(self) -> bool:
        return bool(self["results"] or self["caller_results"] or self.groups or self.result_words)

    def merge(self, params=None, results=None, caller_results=None, result_words: int = 0, groups=None) -> bool:
        """
        Parameter types replace the earlier ones; result types accumulate (over callers, and over passes as callees
        get typed), the first to type a word wins unless a later one types a wider value there. A typed group
        replaces an untyped one of the same span. Returns whether the record changed.
        """
        changed = False
        if params:
            params = list(params)
            if self["params"] != params:
                self["params"] = params
                changed = True
        for table, new in (("results", results), ("caller_results", caller_results)):
            for word, (ty, span) in _words(new).items():
                old = self[table].get(word)
                if old is None or old[1] < span:
                    self[table][word] = (ty, span)
                    changed = True
        for word, (span, ty) in _groups(groups).items():
            old = self.groups.get(word)
            if old is None or old[0] < span or (old[0] == span and old[1] is None and ty is not None):
                self.groups[word] = (span, ty)
                changed = True
        if result_words > self.result_words:
            self["result_words"] = result_words
            changed = True
        return changed

    def result_types(self, floor: int) -> list[str]:
        """
        The result list: callee-side types win, caller-side types fill the gaps, then caller-side groups (an untyped
        group is spelled by ``placeholder_group``), words nobody typed stay ``uintptr``. ``floor`` is the number of
        words the guessed prototype already returns.
        """
        results, caller, groups = self.results, self.caller_results, self.groups
        ends = [w + n for w, (_, n) in (*results.items(), *caller.items())]
        ends += [w + n for w, (n, _) in groups.items()]
        count = max(floor, self.result_words, *ends)
        types: list[str] = []
        w = 0
        while w < count:
            hit = results.get(w)
            if hit is None:
                hit = caller.get(w)
                if hit is not None and any(w < k < w + hit[1] for k in results):
                    hit = None
            if hit is None:
                group = groups.get(w)
                if group is not None and not any(w < k < w + group[0] for k in (*results, *caller)):
                    hit = (group[1] if group[1] is not None else placeholder_group(group[0]), group[0])
            if hit is None:
                types.append("uintptr")
                w += 1
            else:
                types.append(hit[0])
                w += hit[1]
        return types


def available_signature_dbs() -> dict[str, Path]:
    """Installed stdlib signature databases, keyed by minor version (``go1.22``)."""
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


_LAYOUT_FREE_CACHE: dict[tuple[int, str], GoSignatureSet] = {}


def _layout_free_db(db: GoSignatureSet, goarch: str) -> GoSignatureSet:
    key = (id(db), goarch)
    if key not in _LAYOUT_FREE_CACHE:
        _LAYOUT_FREE_CACHE[key] = db.without_layout(goarch)
    return _LAYOUT_FREE_CACHE[key]


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
        self._arg_sizes: dict[int, int] | None = None
        self._inferred: dict[str, GoInferredSignature] = {}
        # call instruction address -> what the caller's reads say about the results of an indirect call there
        self._callsites: dict[int, GoInferredSignature] = {}
        # closure body address -> the record type its parent builds (``struct { F uintptr; X0 T; ... }``)
        self._closures: dict[int, str] = {}
        # bumped by one each time inference changes a record; a decompilation remembers the version it was based on
        self.version: int = 0
        # record key (see ``_key``) -> the counter value at its last change; absent means never written
        self._versions: dict[str, int] = {}
        # the records the decompilation in progress consulted, with the version it saw first (see ``track``)
        self._deps: dict[str, int] | None = None

    #
    # Versioning and dependency tracking
    #

    @staticmethod
    def _callsite_key(addr: int) -> str:
        return f"callsite:{addr:#x}"

    @staticmethod
    def _closure_key(addr: int) -> str:
        return f"closure:{addr:#x}"

    def _tick(self, key: str) -> None:
        self.version += 1
        self._versions[key] = self.version

    def _consult(self, key: str) -> None:
        if self._deps is not None:
            self._deps.setdefault(key, self._versions.get(key, 0))

    def record_version(self, key: str) -> int:
        """The counter value when the record ``key`` (a function name, ``callsite:0x..`` or ``closure:0x..``) last
        changed; 0 when it was never written."""
        return self._versions.get(key, 0)

    def record_fingerprint(self, key: str) -> str | None:
        """A process-independent spelling of the record ``key`` as it is now (None when absent), for comparing what a
        decompilation consulted with what another process knows."""
        if key.startswith("callsite:"):
            rec = self._callsites.get(int(key[9:], 16))
        elif key.startswith("closure:"):
            return self._closures.get(int(key[8:], 16))
        else:
            rec = self._inferred.get(key)
        return None if rec is None else json.dumps(rec, sort_keys=True, default=str)

    @contextlib.contextmanager
    def track(self) -> Iterator[dict[str, int]]:
        """
        Record which inference records are consulted while the block runs, each with the version it had when first
        consulted (``deps``). Nested scopes report to the enclosing one.
        """
        outer = self._deps
        deps: dict[str, int] = {}
        self._deps = deps
        try:
            yield deps
        finally:
            self._deps = outer
            if outer is not None:
                for k, v in deps.items():
                    outer.setdefault(k, v)

    @contextlib.contextmanager
    def untracked(self) -> Iterator[None]:
        """Suspend dependency tracking: for one-off whole-binary scans that are nobody's dependency."""
        outer = self._deps
        self._deps = None
        try:
            yield
        finally:
            self._deps = outer

    def note(self, name: str) -> None:
        """Count the inferred record of ``name`` as consulted by the decompilation in progress."""
        self._consult(normalize_go_func_name(name))

    def deps_current(self, deps: dict[str, int] | None, version: int | None) -> bool:
        """
        Whether a decompilation that started from ``version`` and consulted ``deps`` (key -> version seen) reflects the
        current records: none of them changed since. Without a dependency list only the global counter decides.
        """
        if version is None:
            return False
        if deps is None:
            return version == self.version
        return all(self._versions.get(k, 0) == v for k, v in deps.items())

    def is_current(self, cache) -> bool:
        """Whether the decompilation in ``cache`` (a DecompilationCache) reflects the current inference records."""
        return self.deps_current(getattr(cache, "go_sigs_deps", None), getattr(cache, "go_sigs_version", None))

    def stale_decompilations(self, kb=None) -> list[tuple[int, str]]:
        """The ``(addr, flavor)`` keys of the Go decompilations in ``kb.decompilations`` that are out of date."""
        kb = kb if kb is not None else self._kb
        stale = []
        for key in list(kb.decompilations.cached):
            if key[1] != "go":
                continue
            cache = kb.decompilations.get(key)
            if cache is not None and not self.is_current(cache):
                stale.append(key)
        return stale

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
            goarch = _goarch(project.arch) if project is not None else None
            if goarch is not None and db.goarch is not None and db.goarch != goarch:
                # the database is built for one GOARCH; its layouts do not transfer (word width, alignment)
                db = _layout_free_db(db, goarch)
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
                    return self._with_variadic_spelling(sig, lookup)
                # assembly functions have a DWARF subprogram without parameters; keep looking for a typed one
                empty = empty or sig
        return empty

    def _with_variadic_spelling(self, sig: GoFuncSignature, name: str) -> GoFuncSignature:
        """DWARF spells a variadic parameter as a plain slice; adopt the ``...T`` spelling of another source."""
        if not sig.params:
            return sig
        last = sig.params[-1].type_str
        if not last.startswith("[]"):
            return sig
        for src in self._sources:
            other = src.functions.get(name)
            if other is None or other is sig or len(other.params) != len(sig.params):
                continue
            spelled = other.params[-1].type_str
            if spelled.startswith("...") and spelled[3:] == last[2:]:
                params = [*sig.params[:-1], GoParam(sig.params[-1].name, spelled)]
                return dataclasses.replace(sig, params=params)
        return sig

    def variable_at(self, addr: int) -> GoVariable | None:
        for src in self._sources:
            for var in src.variables.values():
                if var.addr == addr:
                    return var
        # runtime globals located by shape and package variables typed from their initializers
        go_globals = getattr(self._kb, "go_globals", None)
        return go_globals.variable_at(addr) if go_globals is not None else None

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
            proto = self._prototypes[name]
            if proto is None:
                self._consult(name)
            return proto
        sig = self.signature(name) or self._implicit_signature(name)
        proto = self._build_prototype(sig) if sig is not None else None
        self._prototypes[name] = proto
        if proto is None:
            self._consult(name)
        return proto

    def set_inferred(
        self,
        name: str,
        param_types: list[str] | dict | None = None,
        results: dict[int, tuple[str, int]] | None = None,
        caller_results: dict[int, tuple[str, int]] | None = None,
        result_words: int = 0,
        groups: dict[int, tuple[int, str | None]] | None = None,
    ) -> GoInferredSignature:
        """
        Record what was inferred for ``name`` (kept until a real signature appears): parameter types, callee-side
        result types, caller-side result types and word groups, or a whole record (as ``inferred_record`` returns
        it, possibly after a round trip through JSON) in place of the parameter types.
        """
        name = normalize_go_func_name(name)
        rec = self._inferred.get(name)
        changed = False
        if rec is None:
            rec = self._inferred[name] = GoInferredSignature()
            changed = True
        if isinstance(param_types, dict):
            other = param_types
            changed |= rec.merge(
                other.get("params"),
                other.get("results"),
                other.get("caller_results"),
                other.get("result_words", 0),
                other.get("groups"),
            )
            param_types = None
        changed |= rec.merge(param_types, results, caller_results, result_words, groups)
        if changed:
            self._tick(name)
        self._prototypes.pop(name, None)
        return rec

    def set_callsite_inferred(
        self,
        addr: int,
        caller_results: dict[int, tuple[str, int]] | None = None,
        result_words: int = 0,
        groups: dict[int, tuple[int, str | None]] | None = None,
    ) -> GoInferredSignature:
        """
        Record what the caller's reads say about the results of the indirect call at ``addr`` (an interface method
        or closure without a known signature); the next decompilation types the call-site prototype from it.
        """
        rec = self._callsites.get(addr)
        changed = False
        if rec is None:
            rec = self._callsites[addr] = GoInferredSignature()
            changed = True
        if rec.merge(None, None, caller_results, result_words, groups) or changed:
            self._tick(self._callsite_key(addr))
        return rec

    def callsite_record(self, addr: int) -> GoInferredSignature | None:
        self._consult(self._callsite_key(addr))
        return self._callsites.get(addr)

    def inferred(self, name: str) -> list[str] | None:
        """The inferred parameter types of ``name``."""
        rec = self.inferred_record(name)
        return rec.params if rec is not None else None

    def inferred_record(self, name: str) -> GoInferredSignature | None:
        name = normalize_go_func_name(name)
        self._consult(name)
        return self._inferred.get(name)

    def results_guessed(self, func: Function) -> bool:
        """
        True when nothing but the calling-convention guess describes the results of ``func``: its prototype is
        guessed, or it was rebuilt (a promoted receiver, inferred parameters) around the guessed result type.
        """
        if func.is_prototype_guessed:
            return True
        proto = func.prototype
        if proto is None or func.prototype_source.name == "USER":
            return False
        if self.prototype(func.name) is not None or self.prototype_at(func.addr) is not None:
            return False
        if not isinstance(proto.returnty, GoSimType):
            return True
        # an inferred result list with words nobody typed yet may still gain from callees typed since
        rec = self.inferred_record(func.name)
        arch = self._kb._project.arch
        return rec is not None and any(
            is_placeholder_type(t) for t in rec.result_types(_word_count(proto.returnty, arch))
        )

    def untyped_params(self, func: Function) -> frozenset[int]:
        """
        Indices of the parameters of ``func`` that only the calling-convention guess describes: a prototype rebuilt
        around a promoted receiver or inferred results keeps the guessed words (non-Go types, or the ``uintptr`` an
        inferred record spells for words it could not type). Type inference may know better about those, so they
        are no ground truth. Parameters of a real signature always are.
        """
        proto = func.prototype
        if not isinstance(proto, GoSimTypeFunction) or func.prototype_source.name == "USER":
            return frozenset()
        if self.prototype(func.name) is not None or self.prototype_at(func.addr) is not None:
            return frozenset()
        self.note(func.name)
        return frozenset(
            i for i, a in enumerate(proto.args) if not isinstance(a, GoSimType) or go_type_repr(a) == "uintptr"
        )

    def inferred_prototype(self, name: str, guessed) -> GoSimTypeFunction | None:
        """
        The inferred signature of ``name`` as a function type: inferred parameter types (else the guessed ones) and
        inferred result types (else the guessed result type ``guessed.returnty``).
        """
        rec = self.inferred_record(name)
        if rec is None or (rec.params is None and not rec.has_results):
            return None
        arch = self._kb._project.arch
        try:
            if rec.params is not None:
                args = [self.parser.parse(t) for t in rec.params]
            else:
                args = [a.with_arch(arch) for a in guessed.args]
            if rec.has_results:
                floor = _word_count(guessed.returnty, arch)
                results = [self.parser.parse(t) for t in rec.result_types(floor)]
                returnty = results[0] if len(results) == 1 else GoSimTypeTuple(results) if results else None
            else:
                returnty = guessed.returnty
        except Exception:  # pylint:disable=broad-exception-caught
            return None
        names = list(guessed.arg_names[: len(args)]) if rec.params is None and guessed.arg_names else None
        return GoSimTypeFunction(args, returnty, arg_names=names or [f"a{i}" for i in range(len(args))]).with_arch(arch)

    def set_closure_context(self, addr: int, type_str: str) -> None:
        """Record the closure record type a parent function builds for the closure body at ``addr``."""
        if self._closures.get(addr) == type_str:
            return
        self._closures[addr] = type_str
        self._tick(self._closure_key(addr))

    def closure_context(self, addr: int) -> str | None:
        """The closure record type of the body at ``addr`` (captures are its fields after ``F``), if known."""
        self._consult(self._closure_key(addr))
        return self._closures.get(addr)

    def arg_size_at(self, addr: int) -> int | None:
        """The byte size of the parameters of the function at ``addr`` from the pclntab (results excluded)."""
        if self._arg_sizes is None:
            self._arg_sizes = {}
            tab = getattr(self._kb._project.loader.main_object, "gopclntab", None)
            for f in getattr(tab, "functions", None) or ():
                if getattr(f, "args", None) is not None and f.args >= 0:
                    self._arg_sizes[f.addr] = f.args
        return self._arg_sizes.get(addr)

    def prototype_at(self, addr: int) -> GoSimTypeFunction | None:
        """
        The function type of the method whose code starts at ``addr``, from the runtime type descriptors' method
        tables (receiver first). Covers methods of named types in stripped binaries, which no signature source names.
        """
        go_types = getattr(self._kb, "go_types", None)
        method = go_types.method_at(addr) if go_types is not None else None
        if method is None:
            return None
        recv, _name, ftype = method
        try:
            fn = self.parser.parse(ftype)
            recv_ty = self.parser.parse(recv)
        except Exception:  # pylint:disable=broad-exception-caught
            return None
        # "func(...) ..." parses as the func value type wrapping the signature
        fn = getattr(fn, "signature", fn)
        if not isinstance(fn, GoSimTypeFunction):
            return None
        arch = self._kb._project.arch
        return GoSimTypeFunction(
            [recv_ty, *fn.args],
            fn.returnty,
            arg_names=["recv", *(fn.arg_names or [""] * len(fn.args))],
            variadic=fn.variadic,
        ).with_arch(arch)

    def _build_prototype(self, sig: GoFuncSignature) -> GoSimTypeFunction:
        parser = self.parser
        params = sig.all_params
        args = []
        variadic = False
        for p in params:
            if p.type_str.startswith("..."):
                # the last parameter of a variadic function, spelled "...T"
                variadic = True
                args.append(GoSimTypeSlice(parser.parse(p.type_str[3:])))
            else:
                args.append(parser.parse(p.type_str))
        results = [parser.parse(r.type_str) for r in sig.results]
        if not results:
            returnty = None
        elif len(results) == 1:
            returnty = results[0]
        else:
            returnty = GoSimTypeTuple(results, [r.name for r in sig.results])
        arch = self._kb._project.arch
        return GoSimTypeFunction(args, returnty, arg_names=[p.name for p in params], variadic=variadic).with_arch(arch)

    def copy(self):
        o = GoSignatures(self._kb)
        o.go_version = self.go_version
        o._sources = list(self._sources)
        o._stdlib_loaded = self._stdlib_loaded
        o._inferred = dict(self._inferred)
        o._callsites = dict(self._callsites)
        o._closures = dict(self._closures)
        o.version = self.version
        o._versions = dict(self._versions)
        return o


def _word_count(ty, arch) -> int:
    """How many machine words a (guessed) result type occupies."""
    if ty is None or isinstance(ty, SimTypeBottom):
        return 0
    size = ty.with_arch(arch).size
    return max(1, (size or arch.bits) // arch.bits)


KnowledgeBasePlugin.register_default("go_signatures", GoSignatures)
