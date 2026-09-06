from __future__ import annotations

import dataclasses
import json
import logging
import re
from pathlib import Path
from typing import TYPE_CHECKING

from angr.go.analyses.dwarf_signatures import read_go_dwarf_signatures
from angr.go.signature import GoFuncSignature, GoNamedType, GoParam, GoSignatureSet, GoVariable
from angr.go.sim_type import GoSimType, GoSimTypeFunction, GoSimTypeSlice, GoSimTypeTuple
from angr.go.type_parser import GoTypeParser
from angr.go.utils.version import go_minor_version, identify_go_version
from angr.knowledge_plugins.plugin import KnowledgeBasePlugin
from angr.sim_type import SimTypeBottom
from angr.utils.go_runtime import normalize_go_func_name

if TYPE_CHECKING:
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


class GoInferredSignature(dict):
    """
    What the decompiler inferred about a function nobody names: parameter types from the callees its parameters
    reach, and result types from its own return statements (``results``, word -> (type, words spanned)) and from how
    callers use the result registers (``caller_results``). Word indices count ABIInternal result registers. A plain
    dict underneath so records survive JSON and pickling between the processes of a sweep.
    """

    def __init__(self, params=None, results=None, caller_results=None):
        super().__init__(params=list(params) if params else None, results={}, caller_results={})
        self.merge(params=None, results=results, caller_results=caller_results)

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
    def has_results(self) -> bool:
        return bool(self["results"] or self["caller_results"])

    def merge(self, params=None, results=None, caller_results=None) -> None:
        """
        Parameter types replace the earlier ones; result types accumulate (over callers, and over passes as callees
        get typed), the first to type a word wins unless a later one types a wider value there.
        """
        if params:
            self["params"] = list(params)
        for table, new in (("results", results), ("caller_results", caller_results)):
            for word, (ty, span) in _words(new).items():
                old = self[table].get(word)
                if old is None or old[1] < span:
                    self[table][word] = (ty, span)

    def result_types(self, floor: int) -> list[str]:
        """
        The result list: callee-side types win, caller-side types fill the gaps, words nobody typed stay ``uintptr``.
        ``floor`` is the number of words the guessed prototype already returns.
        """
        results, caller = self.results, self.caller_results
        ends = [w + n for w, (_, n) in (*results.items(), *caller.items())]
        count = max(floor, *ends) if ends else floor
        types: list[str] = []
        w = 0
        while w < count:
            hit = results.get(w)
            if hit is None:
                hit = caller.get(w)
                if hit is not None and any(w < k < w + hit[1] for k in results):
                    hit = None
            if hit is None:
                types.append("uintptr")
                w += 1
            else:
                types.append(hit[0])
                w += hit[1]
        return types


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
        self._arg_sizes: dict[int, int] | None = None
        self._inferred: dict[str, GoInferredSignature] = {}

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

    def set_inferred(
        self,
        name: str,
        param_types: list[str] | dict | None = None,
        results: dict[int, tuple[str, int]] | None = None,
        caller_results: dict[int, tuple[str, int]] | None = None,
    ) -> GoInferredSignature:
        """
        Record what was inferred for ``name`` (kept until a real signature appears): parameter types, callee-side
        result types and caller-side result types, or a whole record (as ``inferred_record`` returns it, possibly
        after a round trip through JSON) in place of the parameter types.
        """
        name = normalize_go_func_name(name)
        rec = self._inferred.get(name)
        if rec is None:
            rec = self._inferred[name] = GoInferredSignature()
        if isinstance(param_types, dict):
            other = param_types
            rec.merge(other.get("params"), other.get("results"), other.get("caller_results"))
            param_types = None
        rec.merge(param_types, results, caller_results)
        self._prototypes.pop(name, None)
        return rec

    def inferred(self, name: str) -> list[str] | None:
        """The inferred parameter types of ``name``."""
        rec = self._inferred.get(normalize_go_func_name(name))
        return rec.params if rec is not None else None

    def inferred_record(self, name: str) -> GoInferredSignature | None:
        return self._inferred.get(normalize_go_func_name(name))

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
        rec = self._inferred.get(normalize_go_func_name(func.name))
        arch = self._kb._project.arch
        return rec is not None and "uintptr" in rec.result_types(_word_count(proto.returnty, arch))

    def inferred_prototype(self, name: str, guessed) -> GoSimTypeFunction | None:
        """
        The inferred signature of ``name`` as a function type: inferred parameter types (else the guessed ones) and
        inferred result types (else the guessed result type ``guessed.returnty``).
        """
        rec = self._inferred.get(normalize_go_func_name(name))
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
        return o


def _word_count(ty, arch) -> int:
    """How many machine words a (guessed) result type occupies."""
    if ty is None or isinstance(ty, SimTypeBottom):
        return 0
    size = ty.with_arch(arch).size
    return max(1, (size or arch.bits) // arch.bits)


KnowledgeBasePlugin.register_default("go_signatures", GoSignatures)
