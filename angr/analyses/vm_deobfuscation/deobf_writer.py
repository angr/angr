"""
Serialise everything the decompiler needs about a deobfuscated function, immediately before
``Decompiler`` runs.

The dump is consumed by :mod:`deobf_reader`, which needs no pushan code -- by this point all the
VM-specific surgery (address re-encoding, jumpkind fixing, branch materialisation, sim-proc call
wiring) has already been applied to the graph.

Serialise intent, not internal representation:

* Edges are recorded semantically (``transition``, ``call``, ``return``); the loader replays them
  through the ``Function`` API so each angr version does its own edge bookkeeping.
* Prototypes become C declaration strings.  C syntax is stable across angr versions; ``SimType``
  class layouts are not.
* Calling conventions become class names, with ``"default"`` meaning the arch default.
"""

import gzip
import json
import logging

from .deobf_schema import (
    ADDR_ENCODING_RAW,
    DATA_SENSITIVE_CONST_CLASSES,
    DATA_SENSITIVE_EXPR_CLASSES,
    EXPRESSION_TAGS,
    FORMAT_VERSION,
    STATEMENT_TAGS,
    TMP_TYPE_SENTINEL,
    UnsupportedIRError,
    enc_bytes,
    enc_int,
)

_l = logging.getLogger(__name__)


def _tag_of(obj, tags, kind):
    """Return the bare VEX tag of a statement/expression, rejecting anything unknown."""
    tag = getattr(obj, "tag", None)
    if tag is None:
        raise UnsupportedIRError(f"{kind} {type(obj).__name__} has no tag")
    # pyvex tags look like "Ist_WrTmp" / "Iex_Binop".
    bare = tag.split("_", 1)[1] if "_" in tag else tag
    if bare not in tags:
        raise UnsupportedIRError(f"unsupported {kind} tag {tag} ({type(obj).__name__})")
    return bare


class _Writer:
    def __init__(self, project):
        self.project = project
        self.unrendered_prototypes = []
        self._node_keys = {}
        self._func_keys = {}

    #
    # constants and expressions
    #

    def _const(self, con):
        """Encode a bare ``pyvex.const.IRConst``."""
        cls_name = type(con).__name__
        out = {"ty": con.type, "value": enc_int(con.value)}
        if cls_name in DATA_SENSITIVE_CONST_CLASSES:
            # Downgrade to the plain pyvex class.  ailment dispatches both onto const_n and
            # nothing downstream reads block_id, so keep it only as metadata.
            out["block_id"] = self._block_id(getattr(con, "block_id", None))
        elif cls_name not in ("U1", "U8", "U16", "U32", "U64", "U128", "V128", "V256", "F32", "F32i", "F64", "F64i"):
            raise UnsupportedIRError(f"unsupported IRConst class {cls_name}")
        return out

    def _expr(self, expr):
        if expr is None:
            return None

        cls_name = type(expr).__name__
        tag = _tag_of(expr, EXPRESSION_TAGS, "expression")
        out = {"e": tag}

        if tag == "RdTmp":
            out["tmp"] = expr.tmp
            if cls_name in DATA_SENSITIVE_EXPR_CLASSES:
                out["block_id"] = self._block_id(getattr(expr, "block_id", None))
        elif tag == "Const":
            out["con"] = self._const(expr.con)
        elif tag == "Get":
            out["offset"] = expr.offset
            out["ty"] = expr.ty
        elif tag == "GetI":
            out["descr"] = self._regarray(expr.descr)
            out["ix"] = self._expr(expr.ix)
            out["bias"] = expr.bias
        elif tag == "Load":
            out["end"] = expr.end
            out["ty"] = expr.ty
            out["addr"] = self._expr(expr.addr)
        elif tag in ("Unop", "Binop", "Triop", "Qop"):
            out["op"] = expr.op
            out["args"] = [self._expr(a) for a in expr.args]
        elif tag == "ITE":
            out["cond"] = self._expr(expr.cond)
            out["iftrue"] = self._expr(expr.iftrue)
            out["iffalse"] = self._expr(expr.iffalse)
        elif tag == "CCall":
            out["retty"] = expr.retty
            out["cee"] = expr.cee.name
            out["args"] = [self._expr(a) for a in expr.args]
        elif tag == "Binder":
            out["binder"] = expr.binder
        elif tag in ("VECRET", "GSPTR"):
            pass
        else:
            raise UnsupportedIRError(f"unhandled expression tag {tag}")

        return out

    @staticmethod
    def _regarray(descr):
        return {"base": descr.base, "elemTy": descr.elemTy, "nElems": descr.nElems}

    #
    # statements
    #

    def _stmt(self, stmt):
        tag = _tag_of(stmt, STATEMENT_TAGS, "statement")
        out = {"t": tag}

        if tag == "NoOp":
            pass
        elif tag == "IMark":
            # IMark addresses are re-encoded BlockIDs by the time we get here, so they are huge.
            out["addr"] = enc_int(stmt.addr)
            out["len"] = stmt.len
            out["delta"] = stmt.delta
        elif tag == "AbiHint":
            out["base"] = self._expr(stmt.base)
            out["len"] = stmt.len
            out["nia"] = self._expr(stmt.nia)
        elif tag == "Put":
            out["offset"] = stmt.offset
            out["data"] = self._expr(stmt.data)
        elif tag == "PutI":
            out["descr"] = self._regarray(stmt.descr)
            out["ix"] = self._expr(stmt.ix)
            out["bias"] = stmt.bias
            out["data"] = self._expr(stmt.data)
        elif tag == "WrTmp":
            out["tmp"] = stmt.tmp
            out["data"] = self._expr(stmt.data)
        elif tag == "Store":
            out["end"] = stmt.end
            out["addr"] = self._expr(stmt.addr)
            out["data"] = self._expr(stmt.data)
        elif tag == "StoreG":
            out["end"] = stmt.end
            out["addr"] = self._expr(stmt.addr)
            out["data"] = self._expr(stmt.data)
            out["guard"] = self._expr(stmt.guard)
        elif tag == "LoadG":
            out["end"] = stmt.end
            out["cvt"] = stmt.cvt
            out["dst"] = stmt.dst
            out["addr"] = self._expr(stmt.addr)
            out["alt"] = self._expr(stmt.alt)
            out["guard"] = self._expr(stmt.guard)
        elif tag == "CAS":
            out["oldLo"] = stmt.oldLo
            out["oldHi"] = stmt.oldHi
            out["end"] = stmt.end
            out["addr"] = self._expr(stmt.addr)
            out["expdLo"] = self._expr(stmt.expdLo)
            out["expdHi"] = self._expr(stmt.expdHi)
            out["dataLo"] = self._expr(stmt.dataLo)
            out["dataHi"] = self._expr(stmt.dataHi)
        elif tag == "LLSC":
            out["end"] = stmt.end
            out["result"] = stmt.result
            out["addr"] = self._expr(stmt.addr)
            out["storedata"] = self._expr(stmt.storedata)
        elif tag == "MBE":
            out["event"] = stmt.event
        elif tag == "Dirty":
            out["cee"] = stmt.cee.name
            out["guard"] = self._expr(stmt.guard)
            out["args"] = [self._expr(a) for a in stmt.args]
            out["tmp"] = stmt.tmp
            out["mFx"] = stmt.mFx
            out["mAddr"] = self._expr(stmt.mAddr)
            out["mSize"] = stmt.mSize
            out["nFxState"] = stmt.nFxState
        elif tag == "Exit":
            out["guard"] = self._expr(stmt.guard)
            out["dst"] = self._const(stmt.dst)
            out["jumpkind"] = stmt.jumpkind
            out["offsIP"] = stmt.offsIP
        else:
            raise UnsupportedIRError(f"unhandled statement tag {tag}")

        return out

    #
    # blocks
    #

    def _irsb(self, irsb):
        # tyenv entries may be the literal sentinel "tmp removed" where pushan deleted a temp.
        types = list(irsb.tyenv.types)
        return {
            "addr": enc_int(irsb.addr),
            "arch": irsb.arch.name,
            "jumpkind": irsb.jumpkind,
            "size": irsb.size,
            "direct_next": bool(irsb.direct_next),
            "tyenv": types,
            "statements": [self._stmt(s) for s in irsb.statements],
            "next": self._expr(irsb.next),
        }

    @staticmethod
    def _block_id(block_id):
        if block_id is None:
            return None
        if isinstance(block_id, int):
            return {"kind": "int", "value": enc_int(block_id)}
        callsite_tuples = getattr(block_id, "callsite_tuples", None)
        return {
            "kind": "BlockID",
            "addr": enc_int(block_id.addr),
            "callsite_tuples": None if callsite_tuples is None else [enc_int(t) for t in callsite_tuples],
            "jump_type": block_id.jump_type,
            "vm_vpc": enc_int(block_id.vm_vpc) if isinstance(block_id.vm_vpc, int) else block_id.vm_vpc,
        }

    def _node(self, node, key):
        return {
            "key": key,
            "addr": enc_int(node.addr),
            "size": node.size,
            "name": node._name,
            "simprocedure_name": node.simprocedure_name,
            "no_ret": bool(node.no_ret),
            "is_syscall": bool(node.is_syscall),
            "function_address": enc_int(node.function_address),
            "thumb": bool(node.thumb),
            "byte_string": enc_bytes(node.byte_string),
            "instruction_addrs": [enc_int(a) for a in node.instruction_addrs],
            "block_id": self._block_id(node.block_id),
            "irsb": self._irsb(node.irsb),
        }

    #
    # types and calling conventions
    #

    def _prototype(self, proto, name=None):  # pylint:disable=unused-argument
        """
        Render a prototype as a C declaration that parses back to the same shape.

        The declared name is always ``f``: the real name is stored separately, and this way a
        name that is not a valid C identifier cannot break the declaration.

        ``SimType.c_repr``'s ``full`` knob cannot be trusted here.  ``SimTypeFunction.c_repr``
        renders its arguments with ``full - 1``, so ``full=0`` becomes ``-1`` -- truthy -- and
        argument structs expand into bodies that are not valid C (``union <anon>``, and
        self-referential structs rendered empty).  ``full=1`` fixes the arguments but then
        expands a struct *return* type instead.  So render several candidates and keep the first
        one that parses back to the same shape.
        """
        if proto is None:
            return None

        for candidate in self._decl_candidates(proto):
            if candidate is not None and self._decl_matches(candidate, proto):
                return candidate

        # Known gap: an argument passed *by value* whose type is a struct/array with a real body
        # cannot be reproduced without also emitting the struct definition.  Record the loss
        # rather than emitting a declaration that parses back to a different call shape.
        _l.warning("deobf dump: no faithful C rendering for prototype %r; storing null", proto)
        self.unrendered_prototypes.append(repr(proto))
        return None

    @staticmethod
    def _prototype_arg_names(proto):
        """
        Argument names, kept separately from the C declaration.

        The preferred rendering leaves parameters unnamed (a name that is not a valid C identifier,
        or collides with a keyword, would break the declaration), so carry the names as data.
        """
        if proto is None or not getattr(proto, "args", None):
            return None
        names = list(getattr(proto, "arg_names", None) or [])
        if not any(names):
            return None
        return [(n if n else None) for n in names] + [None] * (len(proto.args) - len(names))

    def _decl_candidates(self, proto):
        # Shallow first: it never expands a struct body, so it stays small and predictable.
        try:
            yield self._shallow_decl(proto)
        except Exception:  # pylint:disable=broad-except
            yield None
        for full in (1, 0):
            try:
                yield proto.c_repr(name="f", full=full)
            except Exception:  # pylint:disable=broad-except
                yield None
        # Last resort: keep the arity and the return type, make every argument opaque.
        try:
            args = ", ".join(["void *"] * len(proto.args or ()))
            if proto.variadic:
                args = f"{args}, ..." if args else "..."
            yield f"{self._shallow_type(proto.returnty)} (f)({args})"
        except Exception:  # pylint:disable=broad-except
            yield None

    def _decl_matches(self, decl, proto):
        """Re-parse `decl` and check it describes the same call shape as `proto`."""
        from angr.sim_type import parse_signature  # pylint:disable=import-outside-toplevel

        try:
            parsed = parse_signature(decl, arch=self.project.arch)
        except Exception:  # pylint:disable=broad-except
            return False
        if len(parsed.args or ()) != len(proto.args or ()):
            return False
        if bool(parsed.variadic) != bool(proto.variadic):
            return False
        arch = self.project.arch
        for got, want in zip(parsed.args or (), proto.args or ()):
            if _type_bits(got, arch) != _type_bits(want, arch):
                return False
        return _type_bits(parsed.returnty, arch) == _type_bits(proto.returnty, arch)

    def _shallow_decl(self, proto):
        """Render a prototype with every struct/union left opaque."""
        args = [self._shallow_type(a) for a in proto.args or ()]
        if proto.variadic:
            args.append("...")
        return f"{self._shallow_type(proto.returnty)} (f)({', '.join(args)})"

    def _shallow_type(self, ty):
        from angr import sim_type  # pylint:disable=import-outside-toplevel

        if ty is None or isinstance(ty, sim_type.SimTypeBottom):
            return "void"
        if isinstance(ty, sim_type.TypeRef):
            return self._shallow_type(ty.type)
        if isinstance(ty, sim_type.SimTypePointer):
            inner = ty.pts_to
            if inner is None or isinstance(inner, (sim_type.SimTypeBottom, sim_type.SimTypeFunction)):
                return "void *"
            return f"{self._shallow_type(inner)} *"
        if isinstance(ty, sim_type.SimTypeArray):
            return f"{self._shallow_type(ty.elem_type)} *"
        if isinstance(ty, sim_type.SimStruct):
            return f"struct {_c_identifier(ty.name)}"
        if isinstance(ty, sim_type.SimUnion):
            return f"union {_c_identifier(ty.name)}"
        return ty.c_repr(name=None, full=0)

    def _cc(self, cc):
        if cc is None:
            return None
        default = self.project.factory._default_cc(self.project.arch)
        if type(cc) is type(default):
            return "default"
        return type(cc).__name__

    def _best_prototype(self, func):
        """
        The most informative prototype available for ``func``.

        ``Function.prototype`` can still be an argument-less placeholder at dump time even when
        this angr knows the real signature: the hook and the library declaration carry it, but
        nothing has copied it onto the function yet.  Read those directly rather than calling
        ``find_declaration()``, which would mutate the producer's state as a side effect of
        dumping.
        """
        proto = func.prototype
        if proto is not None and getattr(proto, "args", None):
            return proto

        for candidate in self._declared_prototypes(func):
            if candidate is not None and getattr(candidate, "args", None):
                try:
                    return candidate.with_arch(self.project.arch)
                except Exception:  # pylint:disable=broad-except
                    return candidate
        return proto

    def _declared_prototypes(self, func):
        """Prototypes this angr can find for ``func`` without touching the function object."""
        try:
            hook = self.project.hooked_by(func.addr)
        except Exception:  # pylint:disable=broad-except
            hook = None
        if hook is not None:
            yield getattr(hook, "prototype", None)

        from angr.procedures.definitions import SIM_LIBRARIES  # pylint:disable=import-outside-toplevel

        try:
            libraries = SIM_LIBRARIES.get(func.binary_name) or ()
        except Exception:  # pylint:disable=broad-except
            return
        # Newer angr maps a library name to a list of SimLibrary; older angr to a single one.
        for library in libraries if isinstance(libraries, (list, tuple)) else (libraries,):
            try:
                yield library.prototypes.get(func.name)
            except Exception:  # pylint:disable=broad-except
                continue

    def _function(self, func, key, in_graph):
        proto = self._best_prototype(func)
        return {
            "key": key,
            "addr": enc_int(func.addr),
            "name": func.name,
            "is_simprocedure": bool(func.is_simprocedure),
            "is_syscall": bool(func.is_syscall),
            "returning": func.returning,
            "prototype": self._prototype(proto),
            "prototype_arg_names": self._prototype_arg_names(proto),
            "calling_convention": self._cc(func.calling_convention),
            # False for functions the decompiler resolves through the knowledge base rather than
            # through a transition-graph edge -- `exit` is deliberately kept out of the graph.
            "in_graph": in_graph,
        }

    #
    # top level
    #

    def dump(self, func, decompiler_kwargs):
        from angr.knowledge_plugins.functions.function import Function  # pylint:disable=import-outside-toplevel

        graph = func.transition_graph

        nodes = []
        callees = []
        for obj in graph.nodes():
            if isinstance(obj, Function):
                key = f"f{len(self._func_keys)}"
                self._func_keys[obj] = key
                callees.append(self._function(obj, key, True))
            else:
                key = f"n{len(self._node_keys)}"
                self._node_keys[obj] = key
                nodes.append(self._node(obj, key))

        # The decompiler resolves a direct call by looking the target up in the knowledge base, so
        # dump every function pushan registered there -- not just the ones wired into the graph.
        for other in self.project.kb.functions.values():
            if other is func or other in self._func_keys:
                continue
            key = f"f{len(self._func_keys)}"
            self._func_keys[other] = key
            callees.append(self._function(other, key, False))

        edges = []
        # `_call_to` installs the fake_return edge itself, so record the call's return site and
        # let the loader's `_call_to` recreate it.
        fakerets = {}
        for src, dst, data in graph.edges(data=True):
            if data.get("type") == "fake_return":
                fakerets.setdefault(src, dst)

        for src, dst, data in graph.edges(data=True):
            etype = data.get("type")
            if etype == "fake_return":
                continue
            if etype in ("call", "syscall"):
                ret = fakerets.get(src)
                edges.append(
                    {
                        "type": etype,
                        "src": self._key(src),
                        "callee": self._key(dst),
                        "ret": self._key(ret) if ret is not None else None,
                        "stmt_idx": data.get("stmt_idx"),
                        "ins_addr": enc_int(data.get("ins_addr")),
                    }
                )
            elif etype == "return":
                edges.append({"type": "return", "callee": self._key(src), "dst": self._key(dst)})
            elif etype in ("transition", "exception"):
                edges.append(
                    {
                        "type": etype,
                        "src": self._key(src),
                        "dst": self._key(dst),
                        "outside": bool(data.get("outside")),
                        "stmt_idx": data.get("stmt_idx"),
                        "ins_addr": enc_int(data.get("ins_addr")),
                    }
                )
            else:
                raise UnsupportedIRError(f"unsupported transition-graph edge type {etype!r}")

        callsite_prototypes = []
        for addr, entry in self.project.kb.callsite_prototypes._prototypes.items():
            cc, proto, manual = _unpack_callsite_prototype(entry)
            if proto is None:
                continue
            callsite_prototypes.append(
                {
                    "addr": enc_int(addr),
                    "cc": self._cc(cc),
                    "prototype": self._prototype(proto),
                    "prototype_arg_names": self._prototype_arg_names(proto),
                    "manual": bool(manual),
                }
            )

        enc_addr_map = []
        for enc_addr, (addr, stmt_idx, block_id) in self.project.enc_stmt_addr_to_original.items():
            enc_addr_map.append(
                {
                    "enc": enc_int(enc_addr),
                    "addr": enc_int(addr),
                    "stmt_idx": stmt_idx,
                    "block_id": self._block_id(block_id),
                }
            )

        loader = self.project.loader
        return {
            "format_version": FORMAT_VERSION,
            "addr_encoding": ADDR_ENCODING_RAW,
            "tmp_type_sentinel": TMP_TYPE_SENTINEL,
            "producer": {
                "tool": "pushan",
                "angr": _version("angr"),
                "pyvex": _version("pyvex"),
                "ailment": _version("ailment"),
                "arch": self.project.arch.name,
            },
            "project": {
                "binary": loader.main_object.binary,
                "arch": self.project.arch.name,
                "base_addr": enc_int(loader.main_object.mapped_base),
            },
            "function": {
                "addr": enc_int(func.addr),
                "name": func.name,
                "prototype": self._prototype(func.prototype),
            "prototype_arg_names": self._prototype_arg_names(func.prototype),
                "calling_convention": self._cc(func.calling_convention),
                "normalized": bool(func.normalized),
                "returning": func.returning,
                "startpoint": self._key(func.startpoint) if func.startpoint is not None else None,
                "ret_sites": [self._key(n) for n in func._ret_sites],
            },
            "nodes": nodes,
            "callees": callees,
            "edges": edges,
            "callsite_prototypes": callsite_prototypes,
            "decompiler_kwargs": _encode_decompiler_kwargs(decompiler_kwargs),
            "enc_addr_map": enc_addr_map,
            # Prototypes that could not be rendered faithfully and were stored as null.
            "unrendered_prototypes": self.unrendered_prototypes,
        }

    def _key(self, obj):
        key = self._node_keys.get(obj)
        if key is not None:
            return key
        key = self._func_keys.get(obj)
        if key is not None:
            return key
        raise UnsupportedIRError(f"transition-graph object not registered: {obj!r}")


def _unpack_callsite_prototype(entry):
    """
    Read one ``kb.callsite_prototypes`` entry, whichever shape this angr stores.

    Older angr maps an address to ``(cc, prototype, manual)``.  Newer angr maps it to
    ``{CallsitePrototypeKind: (cc, prototype)}``, where the public getters default to the
    INFERRED kind and would silently return None for a manual prototype -- so pick the most
    certain kind present instead.
    """
    if not isinstance(entry, dict):
        cc, proto, manual = entry
        return cc, proto, manual

    if not entry:
        return None, None, False
    # Kind values are ordered by certainty: MANUAL > PROPAGATED > INFERRED.
    kind = max(entry, key=lambda k: getattr(k, "value", 0))
    cc, proto = entry[kind]
    return cc, proto, getattr(kind, "name", "") == "MANUAL"


def _c_identifier(name):
    """Make a struct/union tag usable in a C declaration (angr names anonymous ones "<anon>")."""
    cleaned = "".join(c if (c.isalnum() or c == "_") else "_" for c in str(name or "anon"))
    if not cleaned or cleaned[0].isdigit():
        cleaned = f"_{cleaned}"
    return cleaned


def _type_bits(ty, arch):
    """
    Size of a SimType in bits, or None when it cannot be determined.

    Bind the arch first: a prototype pulled off a SimProcedure often has an unbound return type,
    which would otherwise report None and compare unequal to the freshly parsed one.
    """
    if ty is None:
        return None
    try:
        return ty.with_arch(arch).size
    except Exception:  # pylint:disable=broad-except
        try:
            return ty.size
        except Exception:  # pylint:disable=broad-except
            return None


def _encode_decompiler_kwargs(kwargs):
    """Encode the handful of Decompiler kwargs pushan passes.  Addresses become strings."""
    out = {}
    for name, value in kwargs.items():
        if name == "calls_as_rets":
            out[name] = {enc_int(k): v for k, v in (value or {}).items()}
        elif name == "ail_propagator_init_values":
            if value:
                raise UnsupportedIRError("ail_propagator_init_values is not serialisable")
            out[name] = None
        else:
            out[name] = value
    return out


def _version(module_name):
    try:
        module = __import__(module_name)
        return getattr(module, "__version__", None)
    except ImportError:
        return None


def dump_decompilation_input(func, project, path, **decompiler_kwargs):
    """
    Write everything ``Decompiler`` needs about `func` to `path` as gzipped JSON.

    :param func:                The synthetic deobfuscated function, fully wired.
    :param project:             The pushan project (read for arch, kb and the encoded-address map).
    :param path:                Destination path.  ``.gz`` is implied.
    :param decompiler_kwargs:   The kwargs that would be passed to ``Decompiler``.
    """
    doc = _Writer(project).dump(func, decompiler_kwargs)
    payload = json.dumps(doc, indent=None, separators=(",", ":")).encode("utf-8")
    with gzip.open(path, "wb") as fp:
        fp.write(payload)
    _l.info("deobf dump: wrote %s (%d nodes, %d bytes raw)", path, len(doc["nodes"]), len(payload))
    return doc
