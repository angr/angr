"""
Language-level Go function signatures and named-type descriptions.

Every source of Go type information (the stdlib signature database, DWARF, runtime type descriptors, external
tools) is normalized into these records before it is turned into SimTypes. Types are carried as *Go type strings*
in canonical Go syntax with package-path-qualified names, e.g.::

    int  uint8  uintptr  bool  string  error  unsafe.Pointer
    *net/http.Server  []byte  [4]int  map[string][]int  chan<- int  func(int, string) (int, error)
    struct { x int; y int }  interface { Error() string }  any

Rules:
- Named types are qualified with the full import path (``net/http.Server``, ``main.point``, ``os.File``); a type
  from package ``main`` is ``main.T``. Predeclared types (``int``, ``string``, ``error``, ``any``) are bare.
- Struct field lists use ``;`` separators; anonymous (embedded) fields are written as their type.
- Function types never carry parameter names; only signatures do.
- Generic instantiations use the compiler's spelling, e.g. ``slices.Index[[]int,int]``.

JSON form (used by the on-disk signature databases)::

    {
      "go_version": "go1.22.5",
      "goarch": "amd64",
      "functions": {
        "strconv.Atoi": {"params": [["s", "string"]], "results": [["~r0", "int"], ["~r1", "error"]]},
        "os.(*File).Write": {"recv": ["f", "*os.File"], "params": [["b", "[]byte"]],
                             "results": [["n", "int"], ["err", "error"]]}
      },
      "types": {
        "os.File": {"kind": "struct", "size": 8, "align": 8, "fields": [["file", "*os.file", 0]]},
        "error": {"kind": "interface", "methods": [["Error", "func() string"]]},
        "time.Duration": {"kind": "named", "underlying": "int64", "size": 8, "align": 8}
      }
    }

``kind`` is one of ``struct``, ``interface`` and ``named`` (any other named type; ``underlying`` is its Go type
string). Sizes and offsets are in bytes for ``goarch``.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(slots=True)
class GoParam:
    name: str
    type_str: str


@dataclass(slots=True)
class GoFuncSignature:
    """
    A Go function or method signature. ``name`` is the linker symbol name (``pkg.Func``, ``pkg.(*T).Method``,
    ``pkg.T.Method``, ``pkg.Func.func1``).
    """

    name: str
    params: list[GoParam] = field(default_factory=list)
    results: list[GoParam] = field(default_factory=list)
    recv: GoParam | None = None

    @property
    def all_params(self) -> list[GoParam]:
        """Parameters in ABI order: receiver first."""
        return ([self.recv] if self.recv is not None else []) + self.params

    def to_json(self) -> dict:
        d: dict = {
            "params": [[p.name, p.type_str] for p in self.params],
            "results": [[p.name, p.type_str] for p in self.results],
        }
        if self.recv is not None:
            d["recv"] = [self.recv.name, self.recv.type_str]
        return d

    @classmethod
    def from_json(cls, name: str, d: dict) -> GoFuncSignature:
        recv = GoParam(*d["recv"]) if d.get("recv") else None
        return cls(
            name,
            params=[GoParam(n, t) for n, t in d.get("params", [])],
            results=[GoParam(n, t) for n, t in d.get("results", [])],
            recv=recv,
        )


@dataclass(slots=True)
class GoStructField:
    name: str
    type_str: str
    offset: int


@dataclass(slots=True)
class GoNamedType:
    """
    A named Go type. ``kind`` is ``struct`` (``fields`` set), ``interface`` (``methods`` set) or ``named``
    (``underlying`` set).
    """

    name: str
    kind: str
    size: int | None = None
    align: int | None = None
    fields: list[GoStructField] = field(default_factory=list)
    methods: list[tuple[str, str]] = field(default_factory=list)
    underlying: str | None = None

    def to_json(self) -> dict:
        d: dict = {"kind": self.kind}
        if self.size is not None:
            d["size"] = self.size
        if self.align is not None:
            d["align"] = self.align
        if self.kind == "struct":
            d["fields"] = [[f.name, f.type_str, f.offset] for f in self.fields]
        elif self.kind == "interface":
            d["methods"] = [[n, t] for n, t in self.methods]
        else:
            d["underlying"] = self.underlying
        return d

    @classmethod
    def from_json(cls, name: str, d: dict) -> GoNamedType:
        return cls(
            name,
            d["kind"],
            size=d.get("size"),
            align=d.get("align"),
            fields=[GoStructField(n, t, o) for n, t, o in d.get("fields", [])],
            methods=[(n, t) for n, t in d.get("methods", [])],
            underlying=d.get("underlying"),
        )


@dataclass(slots=True)
class GoVariable:
    """A package-level variable: its linker symbol name, (rebased) address and Go type."""

    name: str
    addr: int
    type_str: str


@dataclass(slots=True)
class GoSignatureSet:
    """
    A collection of signatures, named types and package-level variables from one source.
    """

    go_version: str | None = None
    goarch: str | None = None
    functions: dict[str, GoFuncSignature] = field(default_factory=dict)
    types: dict[str, GoNamedType] = field(default_factory=dict)
    variables: dict[str, GoVariable] = field(default_factory=dict)

    def to_json(self) -> dict:
        d = {
            "go_version": self.go_version,
            "goarch": self.goarch,
            "functions": {name: sig.to_json() for name, sig in self.functions.items()},
            "types": {name: ty.to_json() for name, ty in self.types.items()},
        }
        if self.variables:
            d["variables"] = {name: [v.addr, v.type_str] for name, v in self.variables.items()}
        return d

    @classmethod
    def from_json(cls, d: dict) -> GoSignatureSet:
        return cls(
            go_version=d.get("go_version"),
            goarch=d.get("goarch"),
            functions={name: GoFuncSignature.from_json(name, sig) for name, sig in d.get("functions", {}).items()},
            types={name: GoNamedType.from_json(name, ty) for name, ty in d.get("types", {}).items()},
            variables={name: GoVariable(name, addr, ty) for name, (addr, ty) in d.get("variables", {}).items()},
        )
