"""
Rebuild a deobfuscated function from a dump produced by :mod:`deobf_writer`, so that
``project.analyses.Decompiler`` can run on it.

This module imports nothing from pushan -- only pyvex, archinfo and a few angr public classes --
so it can be dropped into any angr tree alongside :mod:`deobf_schema`.
"""

import gzip
import json
import logging

import archinfo
import pyvex

from .deobf_schema import (
    FORMAT_VERSION,
    TMP_TYPE_SENTINEL,
    DeobfFormatError,
    dec_bytes,
    dec_int,
)

_l = logging.getLogger(__name__)


# Dense synthetic address space used when the original encoding is too wide for this angr.
# Matches the layout angr's own VM deobfuscator uses, so the two are directly comparable.
SYNTHETIC_ADDR_BASE = 0x7000_0000_0000_0000
SYNTHETIC_BLOCK_STRIDE = 0x1_0000


class _Reader:
    def __init__(self, project, doc, rewrite_tmp_sentinel=False, renumber_addrs="auto", align_first_imark="auto"):
        self.project = project
        self.doc = doc
        self.arch = project.arch
        self.rewrite_tmp_sentinel = rewrite_tmp_sentinel
        self.sentinel = doc.get("tmp_type_sentinel", TMP_TYPE_SENTINEL)
        self._objs = {}
        self._addr_map = self._build_addr_map(renumber_addrs)
        self._realigned_imarks = 0
        self._imark_defines_block_addr = (
            _ail_block_addr_comes_from_first_imark(self.arch) if align_first_imark == "auto" else bool(align_first_imark)
        )

    #
    # address width adaptation
    #

    def _build_addr_map(self, renumber_addrs):
        """
        Decide whether the dump's synthetic addresses have to be renumbered, and build the map.

        pushan encodes a whole BlockID into an address by concatenating decimal strings, which
        lands at 90-160 bits.  Older angr carries those through fine; newer angr stores AIL
        addresses as u64 and raises OverflowError.  Renumbering is a property of the *consumer*,
        not of the dump, so probe this angr rather than guessing from the format.
        """
        entries = self.doc.get("enc_addr_map") or []
        wide = [e for e in entries if dec_int(e["enc"]) > 0xFFFF_FFFF_FFFF_FFFF]
        if not wide:
            return None
        if renumber_addrs == "auto":
            if not _ail_addresses_are_u64(self.arch):
                return None
        elif not renumber_addrs:
            return None

        # One contiguous range per (vm_vpc, original address), assigned in the order pushan first
        # encoded them, with the statement index as the offset inside the range.
        mapping = {}
        block_bases = {}
        for entry in entries:
            block_id = entry.get("block_id")
            vm_vpc = block_id.get("vm_vpc") if block_id else None
            key = (vm_vpc, entry["addr"])
            base = block_bases.get(key)
            if base is None:
                base = SYNTHETIC_ADDR_BASE + len(block_bases) * SYNTHETIC_BLOCK_STRIDE
                block_bases[key] = base
            stmt_idx = entry["stmt_idx"] or 0
            if stmt_idx >= SYNTHETIC_BLOCK_STRIDE:
                raise DeobfFormatError(f"statement index {stmt_idx} exceeds the synthetic block stride")
            mapping[dec_int(entry["enc"])] = base + stmt_idx

        _l.info(
            "deobf load: renumbering %d synthetic addresses into %d dense blocks "
            "(this angr stores AIL addresses as u64)",
            len(mapping),
            len(block_bases),
        )
        return mapping

    def _addr(self, value):
        """Map a synthetic address through the renumbering, if one is in effect."""
        if value is None or self._addr_map is None:
            return value
        return self._addr_map.get(value, value)

    def _align_first_imark(self, statements, block_addr):
        """
        Make the first IMark of a block carry the block's own address.

        pushan stitches a deobfuscated block together out of instructions from several original
        addresses, so its first IMark often names a *different* synthetic address than the block.
        Older ailment takes the AIL block address from ``irsb.addr`` and never notices; newer
        ailment takes it from the first IMark, which desynchronises the AIL graph from the
        function graph -- the entry block then cannot be found by address, and everything keyed on
        a block address (callsite prototypes, calls_as_rets) misses.

        Only the first instruction's provenance moves, and only for the versions that need it;
        every jump target is keyed on the block address and is unaffected.
        """
        if not self._imark_defines_block_addr:
            return
        for idx, stmt in enumerate(statements):
            if not isinstance(stmt, pyvex.stmt.IMark):
                continue
            if stmt.addr != block_addr:
                statements[idx] = pyvex.stmt.IMark(block_addr, stmt.len, stmt.delta)
                self._realigned_imarks += 1
            return

    #
    # constants and expressions
    #

    def _const(self, enc):
        if enc is None:
            return None
        ty = enc["ty"]
        value = self._addr(dec_int(enc["value"]))
        if not ty.startswith("Ity_I"):
            raise DeobfFormatError(f"unsupported constant type {ty}")
        # Construct directly rather than through the interning pools: many of these values are
        # far wider than their nominal type because they are encoded BlockIDs.
        return pyvex.const.vex_int_class(_bits_of(ty))(value)

    def _expr(self, enc):
        if enc is None:
            return None
        tag = enc["e"]

        if tag == "RdTmp":
            return pyvex.expr.RdTmp.get_instance(enc["tmp"])
        if tag == "Const":
            return pyvex.expr.Const(self._const(enc["con"]))
        if tag == "Get":
            return pyvex.expr.Get(enc["offset"], enc["ty"])
        if tag == "GetI":
            return pyvex.expr.GetI(self._regarray(enc["descr"]), self._expr(enc["ix"]), enc["bias"])
        if tag == "Load":
            return pyvex.expr.Load(enc["end"], enc["ty"], self._expr(enc["addr"]))
        if tag == "Unop":
            return pyvex.expr.Unop(enc["op"], [self._expr(a) for a in enc["args"]])
        if tag == "Binop":
            return pyvex.expr.Binop(enc["op"], [self._expr(a) for a in enc["args"]])
        if tag == "Triop":
            return pyvex.expr.Triop(enc["op"], [self._expr(a) for a in enc["args"]])
        if tag == "Qop":
            return pyvex.expr.Qop(enc["op"], [self._expr(a) for a in enc["args"]])
        if tag == "ITE":
            return pyvex.expr.ITE(self._expr(enc["cond"]), self._expr(enc["iffalse"]), self._expr(enc["iftrue"]))
        if tag == "CCall":
            return pyvex.expr.CCall(
                enc["retty"], _callee(enc["cee"]), [self._expr(a) for a in enc["args"]]
            )
        if tag == "Binder":
            return pyvex.expr.Binder(enc["binder"])
        if tag == "VECRET":
            return pyvex.expr.VECRET()
        if tag == "GSPTR":
            return pyvex.expr.GSPTR()
        raise DeobfFormatError(f"unsupported expression tag {tag}")

    @staticmethod
    def _regarray(enc):
        return pyvex.enums.IRRegArray(enc["base"], enc["elemTy"], enc["nElems"])

    #
    # statements
    #

    def _stmt(self, enc):
        tag = enc["t"]

        if tag == "NoOp":
            return pyvex.stmt.NoOp()
        if tag == "IMark":
            return pyvex.stmt.IMark(self._addr(dec_int(enc["addr"])), enc["len"], enc["delta"])
        if tag == "AbiHint":
            return pyvex.stmt.AbiHint(self._expr(enc["base"]), enc["len"], self._expr(enc["nia"]))
        if tag == "Put":
            return pyvex.stmt.Put(self._expr(enc["data"]), enc["offset"])
        if tag == "PutI":
            return pyvex.stmt.PutI(
                self._regarray(enc["descr"]), self._expr(enc["ix"]), self._expr(enc["data"]), enc["bias"]
            )
        if tag == "WrTmp":
            return pyvex.stmt.WrTmp(enc["tmp"], self._expr(enc["data"]))
        if tag == "Store":
            return pyvex.stmt.Store(self._expr(enc["addr"]), self._expr(enc["data"]), enc["end"])
        if tag == "StoreG":
            return pyvex.stmt.StoreG(
                enc["end"], self._expr(enc["addr"]), self._expr(enc["data"]), self._expr(enc["guard"])
            )
        if tag == "LoadG":
            return pyvex.stmt.LoadG(
                enc["end"],
                enc["cvt"],
                enc["dst"],
                self._expr(enc["addr"]),
                self._expr(enc["alt"]),
                self._expr(enc["guard"]),
            )
        if tag == "CAS":
            return pyvex.stmt.CAS(
                self._expr(enc["addr"]),
                self._expr(enc["dataLo"]),
                self._expr(enc["dataHi"]),
                self._expr(enc["expdLo"]),
                self._expr(enc["expdHi"]),
                enc["oldLo"],
                enc["oldHi"],
                enc["end"],
            )
        if tag == "LLSC":
            return pyvex.stmt.LLSC(
                self._expr(enc["addr"]), self._expr(enc["storedata"]), enc["result"], enc["end"]
            )
        if tag == "MBE":
            return pyvex.stmt.MBE(enc["event"])
        if tag == "Dirty":
            return pyvex.stmt.Dirty(
                _callee(enc["cee"]),
                self._expr(enc["guard"]),
                [self._expr(a) for a in enc["args"]],
                enc["tmp"],
                enc["mFx"],
                self._expr(enc["mAddr"]),
                enc["mSize"],
                enc["nFxState"],
            )
        if tag == "Exit":
            return pyvex.stmt.Exit(
                self._expr(enc["guard"]), self._const(enc["dst"]), enc["jumpkind"], enc["offsIP"]
            )
        raise DeobfFormatError(f"unsupported statement tag {tag}")

    #
    # blocks
    #

    def _irsb(self, enc):
        arch = _arch(enc["arch"])
        types = list(enc["tyenv"])
        if self.rewrite_tmp_sentinel:
            types = [t if t != self.sentinel else "Ity_I8" for t in types]

        tyenv = pyvex.block.IRTypeEnv(arch, types=types)

        block_addr = self._addr(dec_int(enc["addr"]))
        statements = [self._stmt(s) for s in enc["statements"]]
        self._align_first_imark(statements, block_addr)

        return pyvex.IRSB.empty_block(
            arch,
            block_addr,
            statements=statements,
            tyenv=tyenv,
            nxt=self._expr(enc["next"]),
            direct_next=enc["direct_next"],
            jumpkind=enc["jumpkind"],
            size=enc["size"],
        )

    def _node(self, enc, cfg_model):
        from angr.knowledge_plugins.cfg.cfg_node import CFGENode  # pylint:disable=import-outside-toplevel

        node = CFGENode(
            self._addr(dec_int(enc["addr"])),
            enc["size"],
            cfg_model,
            simprocedure_name=enc["simprocedure_name"],
            no_ret=enc["no_ret"],
            function_address=dec_int(enc["function_address"]),
            block_id=self._block_id(enc["block_id"]),
            irsb=self._irsb(enc["irsb"]),
            instruction_addrs=[dec_int(a) for a in enc["instruction_addrs"]],
            thumb=enc["thumb"],
            byte_string=dec_bytes(enc["byte_string"]),
            is_syscall=enc["is_syscall"],
            name=enc["name"],
        )
        return node

    def _block_id(self, enc):
        if enc is None:
            return None
        if enc["kind"] == "int":
            return dec_int(enc["value"])

        callsite_tuples = enc["callsite_tuples"]
        if callsite_tuples is not None:
            callsite_tuples = tuple(dec_int(t) for t in callsite_tuples)
        vm_vpc = enc["vm_vpc"]
        if isinstance(vm_vpc, str):
            vm_vpc = dec_int(vm_vpc)

        # BlockID has moved between angr versions (analyses.cfg.cfg_job_base ->
        # knowledge_plugins.cfg.block_id).  It is only ever a dict key from here on, so a plain
        # tuple is an acceptable stand-in if neither import works.
        cls = _block_id_class()
        if cls is not None:
            try:
                return cls(dec_int(enc["addr"]), callsite_tuples, enc["jump_type"], vm_vpc=vm_vpc)
            except TypeError:
                return cls(dec_int(enc["addr"]), callsite_tuples, enc["jump_type"])
        return (dec_int(enc["addr"]), callsite_tuples, enc["jump_type"], vm_vpc)

    #
    # types and calling conventions
    #

    def _prototype(self, decl, arg_names=None):
        if not decl:
            return None
        from angr.sim_type import parse_signature  # pylint:disable=import-outside-toplevel

        try:
            proto = parse_signature(decl, arch=self.arch).with_arch(self.arch)
        except Exception:  # pylint:disable=broad-except
            _l.warning("deobf load: could not parse prototype %r; ignoring", decl)
            return None
        return _name_prototype_args(proto, arg_names)

    def _cc(self, name):
        if name is None:
            return None
        if name == "default":
            return self.project.factory._default_cc(self.arch)
        from angr import calling_conventions  # pylint:disable=import-outside-toplevel

        cls = getattr(calling_conventions, name, None)
        if cls is None:
            _l.warning("deobf load: unknown calling convention %s; using the arch default", name)
            return self.project.factory._default_cc(self.arch)
        return cls(self.arch)

    #
    # top level
    #

    def load(self):
        from angr.knowledge_plugins.functions.function import Function  # pylint:disable=import-outside-toplevel

        version = self.doc.get("format_version")
        if version != FORMAT_VERSION:
            raise DeobfFormatError(f"unsupported deobf format version {version} (expected {FORMAT_VERSION})")

        dumped_arch = self.doc.get("project", {}).get("arch")
        if dumped_arch and dumped_arch != self.arch.name:
            raise DeobfFormatError(f"dump is for {dumped_arch} but the project is {self.arch.name}")

        cfg_model = self.project.kb.cfgs.new_model("deobf_graph")
        import networkx  # pylint:disable=import-outside-toplevel

        cfg_model.graph = networkx.DiGraph()

        for enc in self.doc["nodes"]:
            self._objs[enc["key"]] = self._node(enc, cfg_model)

        # These nodes live at synthetic addresses with no bytes behind them.  Newer angr keeps a
        # registry so that analyses which lift a block by address (calling-convention recovery,
        # the stack-pointer tracker) see the deobfuscated code instead of failing to lift, plus a
        # project flag telling those analyses to skip body-less nodes such as sim-proc callees.
        synthetic_irsbs = getattr(self.project, "synthetic_irsbs", None)
        if synthetic_irsbs is not None:
            for key, node in self._objs.items():
                if key.startswith("n") and node.irsb is not None:
                    synthetic_irsbs[node.addr] = node.irsb
            if hasattr(self.project, "vm_deobfuscation"):
                self.project.vm_deobfuscation = True

        for enc in self.doc["callees"]:
            callee = self.project.kb.functions.function(
                self._addr(dec_int(enc["addr"])), enc["name"], create=True
            )
            callee.is_simprocedure = enc["is_simprocedure"]
            callee.returning = enc["returning"]
            proto = self._prototype(enc["prototype"], enc.get("prototype_arg_names"))
            if proto is not None:
                callee.prototype = proto
            callee.calling_convention = self._cc(enc["calling_convention"])
            # Newer angr type-hints the callee slot in a transition graph as FuncNode|HookNode,
            # but the Function object itself is what actually gets stored there in both versions.
            self._objs[enc["key"]] = callee

        fdesc = self.doc["function"]
        func = Function(
            self.project.kb.functions,
            self._addr(dec_int(fdesc["addr"])),
            fdesc["name"],
            None,
            is_simprocedure=False,
        )
        func.calling_convention = self._cc(fdesc["calling_convention"])
        func.prototype = self._prototype(fdesc["prototype"], fdesc.get("prototype_arg_names"))
        self.project.kb.functions[func.addr] = func

        # Register every node first, so isolated nodes (a single-block function) survive.
        for key, obj in self._objs.items():
            if key.startswith("n"):
                _register_node(func, obj)

        for edge in self.doc["edges"]:
            etype = edge["type"]
            if etype in ("transition", "exception"):
                func._transit_to(
                    self._objs[edge["src"]],
                    self._objs[edge["dst"]],
                    outside=edge.get("outside", False),
                    ins_addr=dec_int(edge.get("ins_addr")),
                    stmt_idx=edge.get("stmt_idx"),
                    is_exception=etype == "exception",
                )
            elif etype in ("call", "syscall"):
                ret = edge.get("ret")
                func._call_to(
                    self._objs[edge["src"]],
                    self._objs[edge["callee"]],
                    self._objs[ret] if ret is not None else None,
                    stmt_idx=edge.get("stmt_idx"),
                    ins_addr=dec_int(edge.get("ins_addr")),
                )
            elif etype == "return":
                func._return_from_call(self._objs[edge["callee"]], self._objs[edge["dst"]])
            else:
                raise DeobfFormatError(f"unsupported edge type {etype!r}")

        func.normalized = fdesc["normalized"]
        func.returning = fdesc["returning"]
        if fdesc["startpoint"] is not None:
            func.startpoint = self._objs[fdesc["startpoint"]]
        for key in fdesc["ret_sites"]:
            func._ret_sites.add(self._objs[key])

        for enc in self.doc["callsite_prototypes"]:
            proto = self._prototype(enc["prototype"], enc.get("prototype_arg_names"))
            if proto is None:
                continue
            self.project.kb.callsite_prototypes.set_prototype(
                self._addr(dec_int(enc["addr"])), self._cc(enc["cc"]), proto, manual=enc["manual"]
            )

        # Only ever written by pushan, but it is the sole way back from a synthetic address to a
        # real instruction address, so make it available if this angr version has the attribute.
        enc_addr_map = {}
        for enc in self.doc.get("enc_addr_map", []):
            enc_addr_map[self._addr(dec_int(enc["enc"]))] = (
                dec_int(enc["addr"]),
                enc["stmt_idx"],
                self._block_id(enc["block_id"]),
            )
        try:
            self.project.enc_stmt_addr_to_original = enc_addr_map
        except AttributeError:
            pass

        if self._realigned_imarks:
            _l.info(
                "deobf load: realigned the first IMark of %d block(s) to the block address "
                "(this angr takes the AIL block address from the first IMark)",
                self._realigned_imarks,
            )

        unrendered = self.doc.get("unrendered_prototypes") or []
        if unrendered:
            _l.warning("deobf load: %d prototype(s) were not serialisable: %s", len(unrendered), unrendered)

        return func, self._decode_decompiler_kwargs(self.doc["decompiler_kwargs"])

    def _decode_decompiler_kwargs(self, enc):
        out = dict(enc)
        if "calls_as_rets" in out:
            # Keyed by synthetic instruction addresses, so they follow the renumbering.
            out["calls_as_rets"] = {
                self._addr(dec_int(k)): v for k, v in (out["calls_as_rets"] or {}).items()
            }
        return out


def _name_prototype_args(proto, arg_names=None):
    """
    Make sure every argument of a parsed prototype has a name.

    A C declaration need not name its parameters, and the writer's preferred rendering does not.
    Newer angr backfills ``a0``, ``a1``, ... in ``Function.prototype``'s setter, but older angr
    stores the prototype as a plain attribute, so an unnamed argument reaches the C backend and
    trips ``assert name`` in ``type_to_c_repr_chunks``. Do the same normalisation here, preferring
    any names the dump carried.
    """
    args = getattr(proto, "args", None)
    if not args:
        return proto

    existing = list(getattr(proto, "arg_names", None) or [])
    dumped = list(arg_names or [])
    names = []
    for i in range(len(args)):
        name = None
        if i < len(dumped) and dumped[i]:
            name = dumped[i]
        elif i < len(existing) and existing[i]:
            name = existing[i]
        names.append(name or f"a{i}")

    try:
        proto.arg_names = tuple(names)
    except Exception:  # pylint:disable=broad-except
        _l.warning("deobf load: could not set argument names on %r", proto)
    return proto


def _register_node(func, node):
    """``Function._register_nodes(is_local, *nodes)`` became ``_register_node(is_local, node)``."""
    register_many = getattr(func, "_register_nodes", None)
    if register_many is not None:
        register_many(True, node)
    else:
        func._register_node(True, node)


def _block_id_class():
    for module, name in (
        ("angr.analyses.cfg.cfg_job_base", "BlockID"),
        ("angr.knowledge_plugins.cfg.block_id", "BlockID"),
    ):
        try:
            return getattr(__import__(module, fromlist=[name]), name)
        except (ImportError, AttributeError):
            continue
    return None


def _bits_of(ty):
    # "Ity_I64" -> 64
    return int(ty[len("Ity_I") :])


def _arch(name):
    return archinfo.arch_from_id(name)


def _callee(name):
    # A CCall/Dirty callee is only ever read by name downstream.
    return pyvex.enums.IRCallee(0, name, 0xFFFF)


def _ailment():
    try:
        import ailment  # pylint:disable=import-outside-toplevel

        return ailment
    except ImportError:
        try:
            from angr import ailment  # pylint:disable=import-outside-toplevel

            return ailment
        except ImportError:
            return None


def _ail_addresses_are_u64(arch):
    """
    Probe whether this angr's AIL can hold an address wider than 64 bits.

    Rather than inferring it from a version number, convert a one-block IRSB sitting at a
    deliberately huge address and see whether the conversion overflows.
    """
    ailment = _ailment()
    if ailment is None:
        return False

    probe_addr = 1 << 100
    irsb = pyvex.IRSB.empty_block(
        arch,
        probe_addr,
        statements=[pyvex.stmt.IMark(probe_addr, 1, 0)],
        tyenv=pyvex.block.IRTypeEnv(arch, types=[]),
        nxt=pyvex.expr.Const(pyvex.const.vex_int_class(arch.bits)(probe_addr)),
        jumpkind="Ijk_Boring",
        size=1,
    )
    try:
        ailment.IRSBConverter.convert(irsb, ailment.Manager(arch=arch))
    except OverflowError:
        return True
    except Exception:  # pylint:disable=broad-except
        # Any other failure says nothing about address width; do not renumber on a guess.
        return False
    return False


def _ail_block_addr_comes_from_first_imark(arch):
    """
    Probe whether this angr derives an AIL block's address from the first IMark.

    The Python converter used ``irsb.addr``; the Rust one uses the first IMark.  Convert a block
    whose two addresses deliberately disagree and see which one comes back.
    """
    ailment = _ailment()
    if ailment is None:
        return False

    block_addr, imark_addr = 0x4000, 0x8000
    irsb = pyvex.IRSB.empty_block(
        arch,
        block_addr,
        statements=[pyvex.stmt.IMark(imark_addr, 1, 0)],
        tyenv=pyvex.block.IRTypeEnv(arch, types=[]),
        nxt=pyvex.expr.Const(pyvex.const.vex_int_class(arch.bits)(0)),
        jumpkind="Ijk_Boring",
        size=1,
    )
    try:
        block = ailment.IRSBConverter.convert(irsb, ailment.Manager(arch=arch))
    except Exception:  # pylint:disable=broad-except
        return False
    return getattr(block, "addr", block_addr) == imark_addr


def load_decompilation_input(
    project, path, rewrite_tmp_sentinel=False, renumber_addrs="auto", align_first_imark="auto"
):
    """
    Rebuild the deobfuscated function stored at `path`.

    :param project:                 A Project over the same binary the dump was made from.
    :param path:                    Path to a dump written by ``dump_decompilation_input``.
    :param rewrite_tmp_sentinel:    Replace the "tmp removed" tyenv sentinel with ``Ity_I8``.
                                    Only needed if a stricter decompiler trips over it; the
                                    marked temporaries are unreferenced either way.
    :param renumber_addrs:          Whether to pack pushan's very wide synthetic addresses into a
                                    dense 64-bit range.  ``"auto"`` (the default) probes this angr
                                    and renumbers only if it needs it; True/False force the choice.
    :return:                        ``(function, decompiler_kwargs)``
    """
    with gzip.open(path, "rb") as fp:
        doc = json.loads(fp.read().decode("utf-8"))
    return _Reader(
        project,
        doc,
        rewrite_tmp_sentinel=rewrite_tmp_sentinel,
        renumber_addrs=renumber_addrs,
        align_first_imark=align_first_imark,
    ).load()
