from __future__ import annotations

import logging
from collections import Counter, defaultdict
from typing import TYPE_CHECKING, cast

from angr.ailment import AILBlockViewer
from angr.ailment.expression import (
    BinaryOp,
    Call,
    Const,
    Convert,
    Expression,
    Extract,
    Insert,
    Load,
    Phi,
    StringLiteral,
    Struct,
    UnaryOp,
    VirtualVariable,
)
from angr.ailment.expression import VirtualVariableCategory as VVC
from angr.ailment.statement import Assignment, ConditionalJump, Return, SideEffectStatement, Statement, Store
from angr.analyses.decompiler.optimization_passes.optimization_pass import OptimizationPass, OptimizationPassStage
from angr.analyses.decompiler.variable_map import variable_map_of
from angr.enums import Flavors
from angr.go.sim_type import (
    GoSimStruct,
    GoSimType,
    GoSimTypeFunction,
    GoSimTypeInterface,
    GoSimTypePointer,
    GoSimTypeSlice,
    GoSimTypeString,
    go_type_repr,
)
from angr.go.utils.names import call_target_name
from angr.go.utils.types import go_type_name_at
from angr.utils.go_runtime import normalize_go_func_name
from angr.utils.ssa.vvar_uses_collector import VVarUsesCollector

from .result_widener import RET_FLOOR_TAG
from .value_fuser import _leaf_count, _load_base_and_offset

if TYPE_CHECKING:
    from angr.sim_type import SimType

l = logging.getLogger(__name__)

Words = dict[int, tuple[str, int]]  # word index -> (Go type string, words spanned)

# how often each caller-side grouping rule fired in this process (2a: interface pair, 2b: empty interface, 2c:
# fused read, prefix: a whole result handed to a narrower consumer)
RULE_HITS: Counter = Counter()

# a nil-checked word with one of these is the itab word of an interface pair
_IFACE_FLAGS = frozenset({"typeload", "method", "helper", "boxed", "itab"})

_IFACE_HELPERS = frozenset(
    {"runtime.ifaceeq", "runtime.assertI2I", "runtime.assertI2I2", "runtime.convI2I", "runtime.typeAssert"}
)
_EFACE_HELPERS = frozenset({"runtime.efaceeq", "runtime.assertE2I", "runtime.assertE2I2"})
# a two-word value handed whole to one of these is a string
_STRING_HELPERS = frozenset({"runtime.printstring", "runtime.stringtoslicebyte", "runtime.stringtoslicerune"})
_LENGTH_HELPERS = frozenset(
    {
        "runtime.memequal",
        "runtime.cmpstring",
        "runtime.slicebytetostring",
        "runtime.concatstring2",
        "runtime.concatstring3",
        "runtime.concatstring4",
        "runtime.concatstring5",
        "runtime.concatstrings",
        "runtime.intstring",
        "runtime.slicerunetostring",
        "runtime.stringtoslicebyte",
    }
)


class GoPrototypeInference(OptimizationPass):
    """
    Infer the signature of a function nobody names (no DWARF, not in the signature database, not a method) from the
    typed code around it:

    - parameters, from how they reach callees whose prototypes are known: a parameter word passed where a callee
      takes an ``int`` is an int, two consecutive words fused into ``io.Writer`` for a callee are an ``io.Writer``;
    - results, from what its return statements put in the result registers (a ``new(T)`` gives ``*T``, a constant
      string header a ``string``, an itab an interface, a known callee's result its type) and from how callers use
      the result registers of calls to it (passed to a typed callee, returned through a typed prototype, stored into
      a typed field, compared against an itab).

    Everything is recorded in ``kb.go_signatures`` as an inferred signature; it takes effect the next time the
    function is decompiled (the argument variables and return sites are built before any pass runs).
    """

    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.BEFORE_VARIABLE_RECOVERY
    NAME = "Infer Go signatures from typed callers and callees"

    def __init__(self, func, manager, **kwargs):
        super().__init__(func, manager, **kwargs)
        self._values: _Values | None = None
        self.analyze()

    def _check(self):
        return self.project.is_go_binary and self._arg_vvars is not None, None

    def _analyze(self, cache=None):
        sigs = self.kb.go_signatures
        self._values = _Values(self)
        params = self._infer_params() if self._func.is_prototype_guessed_for(Flavors.GO_FLAVOR) else None
        results_guessed = sigs.results_guessed(self._func)
        results = self._infer_results() if results_guessed else None
        if params or results:
            sigs.set_inferred(self._func.name, params, results)
            l.debug("Inferred %s(%s) -> %s from its own body", self._func.name, params, results)
        self._infer_caller_results()
        if results_guessed:
            self._trim_returns()

    #
    # Parameters
    #

    def _infer_params(self) -> list[str] | None:
        assert self._arg_vvars is not None
        assert self._values is not None
        words: dict[int, int] = {}  # param vvar varid -> word index
        for _, (vvar, _arg) in sorted(self._arg_vvars.items(), key=lambda kv: kv[0]):
            if isinstance(vvar, VirtualVariable) and not vvar.was_combo_reg:
                words[vvar.varid] = len(words)
        if not words:
            return None
        found: dict[int, tuple[str, int]] = {}  # word -> (type string, words spanned)
        for call in self._values.all_calls:
            if not call.args:
                continue
            if call.tags.get("go_render") == "box":
                # box(value): the boxed value has the box's concrete type
                arg_types = [self._type_named(call.tags.get("go_box_type"))]
            else:
                proto = self._callee_prototype(call)
                if proto is None:
                    continue
                arg_types = list(proto.args)
            for arg, ty in zip(call.args, arg_types):
                if not isinstance(ty, GoSimType) or not ty.size:
                    continue
                span = ty.size // self.project.arch.bits
                if isinstance(arg, VirtualVariable) and arg.varid in words and span == 1:
                    _record(found, words[arg.varid], go_type_repr(ty), 1)
                elif isinstance(arg, Struct) and span >= 2:
                    pieces = [arg.fields[off] for off in sorted(arg.fields)]
                    if len(pieces) != span or not all(
                        isinstance(p, VirtualVariable) and p.varid in words for p in pieces
                    ):
                        continue
                    idx = [words[p.varid] for p in pieces]
                    if idx == list(range(idx[0], idx[0] + span)):
                        _record(found, idx[0], go_type_repr(ty), span)
        self._note_param_type_checks(words, found)
        if not found:
            return None
        # assemble the parameter list: typed groups where known, the guessed word type elsewhere
        types: list[str] = []
        w = 0
        while w < len(words):
            hit = found.get(w)
            if hit is not None:
                types.append(hit[0])
                w += hit[1]
            else:
                types.append("uintptr")
                w += 1
        return types

    def _note_param_type_checks(self, words: dict[int, int], found: dict) -> None:
        """
        A parameter word compared against an itab (``w == &go:itab.T,I``) is the first word of an ``I`` value;
        against a type descriptor, of an ``any``. The type switch and assertion checks of an interface parameter.
        Register parameters only: two stack words do not fuse into one parameter.
        """
        assert self._arg_vvars is not None and self._values is not None
        reg_words = {
            words[vvar.varid]
            for vvar, _ in self._arg_vvars.values()
            if isinstance(vvar, VirtualVariable)
            and vvar.varid in words
            and vvar.category == VVC.PARAMETER
            and vvar.parameter_category == VVC.REGISTER
        }
        for call in self._values.all_calls:
            # runtime.typeAssert(&D, typ): a parameter word handed over as the type is an empty interface's
            args = list(call.args or ())
            name = call_target_name(self.project, call)
            if len(args) == 2 and name is not None and normalize_go_func_name(name) == "runtime.typeAssert":
                x = self._values.resolve(args[1])
                if isinstance(x, VirtualVariable) and x.varid in words:
                    word = words[x.varid]
                    if word in reg_words and word + 1 in reg_words:
                        _record(found, word, "any", 2)
        for block in self._graph.nodes:
            last = block.statements[-1] if block.statements else None
            if not isinstance(last, ConditionalJump):
                continue
            cond = last.condition
            if not (isinstance(cond, BinaryOp) and cond.op in ("CmpEQ", "CmpNE")):
                continue
            for x, y in ((cond.operands[0], cond.operands[1]), (cond.operands[1], cond.operands[0])):
                if not (isinstance(y, Const) and y.is_int and y.value_int):
                    continue
                x = self._values.resolve(x)
                if not isinstance(x, VirtualVariable):
                    continue
                # a loop-carried type word: the parameter word is one of the phi's sources
                src = self._values.defs.get(x.varid)
                candidates = [x]
                if isinstance(src, Phi):
                    candidates += [self._values.resolve(v) for _, v in src.src_and_vvars if v is not None]
                for cand in candidates:
                    if not (isinstance(cand, VirtualVariable) and cand.varid in words):
                        continue
                    word = words[cand.varid]
                    if word not in reg_words or word + 1 not in reg_words:
                        continue
                    itab = self.kb.go_types.itab_at(y.value_int)
                    if itab is not None:
                        _record(found, word, itab[0], 2)
                    elif self.kb.go_types.name_at(y.value_int) is not None:
                        _record(found, word, "any", 2)

    def _type_named(self, name) -> SimType | None:
        if not isinstance(name, str):
            return None
        try:
            return self.kb.go_signatures.type(name).with_arch(self.project.arch)
        except Exception:  # pylint:disable=broad-exception-caught
            return None

    def _callee_prototype(self, call: Call) -> GoSimTypeFunction | None:
        proto = variable_map_of(self.manager).prototype(call)
        if isinstance(proto, GoSimTypeFunction):
            return proto
        target = call.target.value if isinstance(call.target, Const) else None
        if isinstance(target, int) and self.kb.functions.contains_addr(target):
            proto = self.kb.functions.get_by_addr(target, meta_only=True).get_prototype(Flavors.GO_FLAVOR)
            if isinstance(proto, GoSimTypeFunction):
                return proto
        return None

    #
    # Results, callee side: what the return statements carry
    #

    def _infer_results(self) -> Words | None:
        found: Words = {}
        conflicts: set[int] = set()
        for block in self._graph.nodes:
            for stmt in block.statements:
                if not isinstance(stmt, Return) or not stmt.ret_exprs:
                    continue
                leaves = self._flatten(list(stmt.ret_exprs))
                w = 0
                while w < len(leaves):
                    hit = leaves[w] if isinstance(leaves[w], tuple) else self._classify(leaves, w, depth=0)
                    if hit is None:
                        w += 1
                        continue
                    ty, span = hit
                    old = found.get(w)
                    if old is not None and old[1] == span and old[0] != ty:
                        conflicts.add(w)
                    _record(found, w, ty, span)
                    w += span
        for w in conflicts:
            # disagreeing returns keep the guess for that word
            found.pop(w, None)
        return found or None

    def _flatten(self, exprs: list) -> list:
        """
        One entry per result word: the word's expression, or an already known (type, words) for a fused value the
        value fuser rebuilt from an applied prototype (a re-inference pass).
        """
        out: list = []
        bytes_ = self.project.arch.bytes
        for expr in exprs:
            if isinstance(expr, Struct):
                out.extend(self._flatten([expr.fields[off] for off in sorted(expr.fields)]))
            elif isinstance(expr, VirtualVariable) and expr.reg_vvars:
                out.extend(expr.reg_vvars)
            elif isinstance(expr, StringLiteral):
                out.append(("string", 2))
            elif isinstance(expr, Call) and expr.tags.get("go_render") == "box":
                out.append((self._box_interface(expr), 2))
            elif isinstance(expr, Load) and expr.size > bytes_ and expr.size % bytes_ == 0:
                pieces = self._combo_piece_of(expr)
                out.extend(pieces if pieces is not None else self._word_loads(expr))
            else:
                out.append(expr)
        return out

    def _word_loads(self, load: Load) -> list[Load]:
        """A wide load (a string or slice read from memory) as one load per word."""
        bits = self.project.arch.bits
        bytes_ = self.project.arch.bytes
        base, off = _addr_base_and_offset(load.addr)
        out = []
        for k in range(load.size // bytes_):
            const = Const(self.manager.next_atom(), off + k * bytes_, bits)
            addr = const if base is None else BinaryOp(self.manager.next_atom(), "Add", [base, const], bits=bits)
            out.append(Load(self.manager.next_atom(), addr, bytes_, load.endness, **load.tags))
        return out

    def _box_interface(self, box: Call) -> str:
        """The interface type a ``box(value)`` call (the boxing rewriter's) builds: its result type, else its name."""
        proto = variable_map_of(self.manager).prototype(box)
        if isinstance(proto, GoSimTypeFunction) and isinstance(proto.returnty, GoSimType):
            return go_type_repr(proto.returnty)
        return box.target if isinstance(box.target, str) else "any"

    def _combo_piece_of(self, load: Load) -> list | None:
        """The register vvars a ``Load(&combo + off, size)`` covers."""
        addr, off = _addr_base_and_offset(load.addr)
        if not (isinstance(addr, UnaryOp) and addr.op == "Reference" and isinstance(addr.operand, VirtualVariable)):
            return None
        regs = addr.operand.reg_vvars
        bytes_ = self.project.arch.bytes
        if not regs or off % bytes_ or load.size % bytes_:
            return None
        pieces = regs[off // bytes_ : (off + load.size) // bytes_]
        return pieces if len(pieces) == load.size // bytes_ else None

    def _classify(self, leaves: list, i: int, depth: int) -> tuple[str, int] | None:
        """The Go type of the value whose first word is ``leaves[i]`` and how many of the leaves it spans."""
        assert self._values is not None
        if isinstance(leaves[i], tuple):
            return leaves[i]
        if isinstance(leaves[i], Extract):
            inserted = self._wide_word(leaves[i])
            if inserted is not None:
                return self._classify([*leaves[:i], inserted, *leaves[i + 1 :]], i, depth)
            if self._phi_operands(leaves[i]) is not None:
                return self._classify_phi(leaves, i, depth)
        expr = self._values.resolve(leaves[i])
        if isinstance(expr, BinaryOp) and expr.op == "Add":
            base = self._values.resolve(expr.operands[0])
            hit = self._values.combo_of.get(base.varid) if isinstance(base, VirtualVariable) else None
            if hit is not None:
                return self._classify_combo_word(leaves, i, hit[0], hit[1])
        if isinstance(expr, VirtualVariable):
            ty = self._values.param_types.get(expr.varid)
            if isinstance(ty, GoSimType) and ty.size == self.project.arch.bits:
                return go_type_repr(ty), 1
            hit = self._values.combo_of.get(expr.varid)
            if hit is not None:
                return self._classify_combo_word(leaves, i, hit[0], hit[1])
            src = self._values.defs.get(expr.varid)
            if isinstance(src, Call):
                return self._single_result(src, leaves, i)
            if isinstance(src, Phi):
                return self._classify_phi(leaves, i, depth)
            if isinstance(src, Convert):
                if src.from_bits == 1:
                    return "bool", 1
                return None
            if isinstance(src, (Load, Const)):
                expr = src
        if isinstance(expr, Const) and expr.is_int:
            return self._classify_const(leaves, i, expr.value_int)
        if isinstance(expr, (Convert, BinaryOp)):
            # a narrow field widened to its register
            stripped = self._strip_widening(expr)
            if isinstance(stripped, Load):
                expr = stripped
        if isinstance(expr, Load):
            piece = self._combo_piece_of(expr) if expr.size == self.project.arch.bytes else None
            if piece:
                hit = self._values.combo_of.get(piece[0].varid)
                if hit is not None:
                    return self._classify_combo_word(leaves, i, hit[0], hit[1])
            return self._classify_load(leaves, i, expr)
        return None

    def _combo_words(self, combo: VirtualVariable) -> list:
        """Per register word of a fused parameter or call result: (type, word within it, words), None if untyped."""
        assert self._values is not None
        ty = self._values.param_types.get(combo.varid)
        if ty is not None:
            return _value_words([ty])
        call = self._values.defs.get(combo.varid)
        if not isinstance(call, Call):
            return []
        proto = self._callee_prototype(call)
        if proto is None:
            return []
        words = _result_words(proto)
        if len(words) == 3 and _untyped_slice_header(words):
            # growslice/moveSliceNoCap return the runtime's untyped header; the element descriptor argument types it
            elem = self._slice_elem_of(call)
            words = _value_words([elem]) if elem is not None else []
        return words

    def _classify_combo_word(self, leaves, i, combo: VirtualVariable, word: int) -> tuple[str, int] | None:
        """A register of a multi-word call result or parameter: the typed value that starts at this word."""
        assert self._values is not None
        words = self._combo_words(combo)
        if word >= len(words) or words[word] is None:
            return None
        ty, start, span = words[word]
        if start != 0:
            return None
        ids = [rv.varid for rv in combo.reg_vvars or []]
        wanted = ids[word : word + span]
        got = [self._values.resolve(self._wide_word(x) or x) for x in leaves[i : i + span]]
        if len(wanted) != span or len(got) != span:
            return None
        if all(isinstance(g, VirtualVariable) and g.varid == v for g, v in zip(got, wanted)):
            repr_ = go_type_repr(ty)
            # "uintptr" spells a word nobody typed (a guessed or caller-bound result): no evidence
            return (repr_, span) if repr_ != "uintptr" else None
        if isinstance(ty, GoSimTypeSlice) and span == 3:
            return self._classify_resliced(leaves, i, combo, word, ty)
        return None

    def _classify_resliced(self, leaves, i, combo: VirtualVariable, word: int, ty) -> tuple[str, int] | None:
        """``s[k:]`` of a typed slice: (ptr + k*w, len - k, cap - k) over the words of ``s``."""
        assert self._values is not None
        ids = [rv.varid for rv in combo.reg_vvars or []][word : word + 3]
        if len(ids) != 3 or i + 2 >= len(leaves):
            return None
        for k, op in enumerate(("Add", "Sub", "Sub")):
            leaf = self._values.resolve(leaves[i + k])
            # the pointer advances by a masked amount (no advance past an empty slice), the lengths by a constant
            if isinstance(leaf, BinaryOp) and leaf.op == op and (k == 0 or isinstance(leaf.operands[1], Const)):
                leaf = self._values.resolve(leaf.operands[0])
            if not isinstance(leaf, VirtualVariable) or leaf.varid != ids[k]:
                return None
        return go_type_repr(ty), 3

    def _slice_elem_of(self, call: Call):
        """``[]T`` for a runtime slice helper (``growslice``, ``moveSliceNoCap``) called with the descriptor of T."""
        name = call_target_name(self.project, call)
        if name is None or not normalize_go_func_name(name).startswith("runtime."):
            return None
        elem = next((e for e in (self._descriptor_arg(call, i) for i in range(len(call.args or []))) if e), None)
        if elem is None:
            return None
        try:
            return self.kb.go_signatures.type(f"[]{elem}")
        except Exception:  # pylint:disable=broad-exception-caught
            return None

    def _single_result(self, call: Call, leaves=None, i: int = 0) -> tuple[str, int] | None:
        proto = self._callee_prototype(call)
        if proto is None:
            return None
        results = proto.results
        if len(results) != 1 or not isinstance(results[0], GoSimType) or results[0].size != self.project.arch.bits:
            return None
        name = call_target_name(self.project, call)
        name = normalize_go_func_name(name) if name is not None else ""
        if name == "make":
            # the rewritten makeslice: its pointer word, with the len and cap words following
            made = (call.tags.get("go_type_args") or [None])[0]
            if isinstance(made, str) and made.startswith("[]") and leaves is not None and i + 2 < len(leaves):
                return made, 3
            return None
        if name in ("runtime.makeslice", "runtime.makeslicecopy"):
            # the pointer word of a fresh slice; the len and cap words follow
            elem = self._descriptor_arg(call, 0)
            if elem is not None and leaves is not None and i + 2 < len(leaves):
                return f"[]{elem}", 3
            return None
        repr_ = go_type_repr(results[0])
        if name.startswith("runtime.") and repr_ == "unsafe.Pointer":
            # allocation helpers return the raw word of whatever they built
            return None
        return repr_, 1

    def _descriptor_arg(self, call: Call, index: int) -> str | None:
        args = list(call.args or [])
        if index >= len(args):
            return None
        arg = args[index]
        return go_type_name_at(self.project, arg.value_int) if isinstance(arg, Const) and arg.is_int else None

    def _classify_phi(self, leaves, i, depth: int) -> tuple[str, int] | None:
        """Leaves defined by phis over the same blocks are classified per incoming block and must agree."""
        assert self._values is not None
        if depth > 2:
            return None
        phis = []
        for leaf in leaves[i:]:
            operands = self._phi_operands(leaf)
            if operands is None:
                break
            phis.append(operands)
            if len(phis) == 3:
                break
        if not phis:
            return None
        sources = [s for s in phis[0] if all(s in p for p in phis)]
        best = None
        for s in sources:
            column = [p[s] for p in phis]
            if any(v is None for v in column):
                continue
            hit = self._classify(column, 0, depth + 1)
            if hit is None:
                continue
            if best is None or best[1] < hit[1]:  # pylint:disable=unsubscriptable-object
                best = hit
            elif best[0] != hit[0] and best[1] == hit[1]:  # pylint:disable=unsubscriptable-object
                return None
        return best

    def _phi_operands(self, leaf) -> dict | None:
        """
        The incoming values of a leaf defined by a phi, per source block: the phi's operands, or, for a word
        extracted from a wide stack slot that is a phi, that word of each incoming slot value.
        """
        assert self._values is not None
        if isinstance(leaf, tuple):
            return None
        extract = None
        r = self._values.resolve(leaf)
        if isinstance(leaf, Extract) and isinstance(leaf.offset, Const) and leaf.offset.is_int:
            extract = leaf
            r = self._values.resolve(leaf.base)
        src = self._values.defs.get(r.varid) if isinstance(r, VirtualVariable) else None
        if not isinstance(src, Phi):
            return None
        out = {}
        for block, vvar in src.src_and_vvars:
            if vvar is None:
                out[block] = None
            elif extract is None:
                out[block] = vvar
            else:
                out[block] = Extract(
                    self.manager.next_atom(), extract.bits, vvar, extract.offset, extract.endness, **extract.tags
                )
        return out

    def _wide_word(self, expr):
        """``Extract(slot, k)`` where the slot is built by ``Insert``s: the value inserted at word ``k``."""
        assert self._values is not None
        if not (isinstance(expr, Extract) and isinstance(expr.offset, Const) and expr.offset.is_int):
            return None
        want = expr.offset.value_int
        base = self._values.resolve(expr.base)
        seen = set()
        while isinstance(base, VirtualVariable) and base.varid not in seen:
            seen.add(base.varid)
            src = self._values.defs.get(base.varid)
            if not (isinstance(src, Insert) and isinstance(src.offset, Const) and src.offset.is_int):
                return None
            if src.offset.value_int == want and src.value.bits == expr.bits:
                return src.value
            base = self._values.resolve(src.base)
        return None

    def _classify_const(self, leaves, i, value: int) -> tuple[str, int] | None:
        if value == 0:
            return None
        if i + 1 < len(leaves):
            itab = self.kb.go_types.itab_at(value)
            if itab is not None:
                return itab[0], 2
            if go_type_name_at(self.project, value) is not None:
                # a type descriptor followed by a data word: an empty interface
                return "any", 2
            nxt = self._values.resolve(leaves[i + 1]) if self._values is not None else leaves[i + 1]
            if isinstance(nxt, Const) and nxt.is_int and 0 < nxt.value_int <= 0x10000 and self._is_readonly(value):
                return "string", 2
        return None

    def _classify_load(self, leaves, i, load: Load) -> tuple[str, int] | None:
        """A load from a field of a typed pointer (a parameter, a ``new(T)`` or a typed call result)."""
        assert self._values is not None
        parsed = _load_base_and_offset(load)
        if parsed is None:
            return None
        base, off = parsed
        if base is None:
            # a package-level variable a source (DWARF) typed
            var = self.kb.go_signatures.variable_at(off)
            if var is None:
                return None
            try:
                fty = self.kb.go_signatures.type(var.type_str)
            except Exception:  # pylint:disable=broad-exception-caught
                return None
        else:
            pointee = self._pointee_type(base)
            if not isinstance(pointee, GoSimStruct):
                return None
            if off == 0:
                whole = self._classify_struct_fields(leaves, i, base, pointee)
                if whole is not None:
                    return whole
            if off == 0 and isinstance(pointee, (GoSimTypeString, GoSimTypeSlice, GoSimTypeInterface)):
                # the words of a string/slice/interface behind a pointer (an element of a typed slice)
                fty = pointee
            else:
                fty = _field_at(pointee, off)
        if not isinstance(fty, GoSimType) or not fty.size:
            return None
        span = _leaf_count(fty)
        if span == 1:
            return (go_type_repr(fty), 1) if fty.size == load.bits else None
        # the following leaves must load the next words of the same value
        for k in range(1, span):
            if i + k >= len(leaves):
                return None
            nxt = _load_base_and_offset(self._values.resolve(leaves[i + k]))
            if nxt is None or nxt[1] != off + k * self.project.arch.bytes:
                return None
            if (base is None) != (nxt[0] is None) or (base is not None and not nxt[0].likes(base)):
                return None
        return go_type_repr(fty), span

    def _classify_struct_fields(self, leaves, i, base: Expression, struct: GoSimStruct) -> tuple[str, int] | None:
        """
        ``p.F0, p.F1, ..., p.Fn`` over every scalar field of ``*p``, in order: the struct by value (ABIInternal gives
        each field of a small struct its own register, ``color.RGBA`` takes four).
        """
        if isinstance(struct, (GoSimTypeString, GoSimTypeSlice, GoSimTypeInterface)):
            return None
        all_fields = _scalar_fields(struct, 0)
        fields = [f for f in all_fields if f is not None]
        if len(all_fields) < 2 or i + len(all_fields) > len(leaves) or len(fields) != len(all_fields):
            return None
        for k, (foff, fsize) in enumerate(fields):
            load = self._strip_widening(leaves[i + k])
            parsed = _load_base_and_offset(load) if isinstance(load, Load) else None
            if parsed is None or parsed[1] != foff or load.size != fsize:
                return None
            if parsed[0] is None or not self._same_value(parsed[0], base):
                return None
        return go_type_repr(struct), len(fields)

    def _strip_widening(self, expr):
        """A narrow value widened to a register: ``Convert`` up, or ``x & 0xff``."""
        assert self._values is not None
        for _ in range(4):
            expr = self._values.resolve(expr)
            if isinstance(expr, VirtualVariable):
                src = self._values.defs.get(expr.varid)
                if isinstance(src, (Load, Convert, BinaryOp)):
                    expr = src
            if isinstance(expr, Convert) and expr.to_bits >= expr.from_bits:
                expr = expr.operand
            elif (
                isinstance(expr, BinaryOp)
                and expr.op == "And"
                and isinstance(expr.operands[1], Const)
                and expr.operands[1].value_int in (0xFF, 0xFFFF, 0xFFFFFFFF)
            ):
                expr = expr.operands[0]
            else:
                break
        return expr

    def _same_value(self, a: Expression, b: Expression) -> bool:
        a, b = self._resolve_phi(a), self._resolve_phi(b)
        if isinstance(a, VirtualVariable) and isinstance(b, VirtualVariable):
            return a.varid == b.varid
        return a.likes(b)

    def _resolve_phi(self, expr: Expression) -> Expression:
        """Look through copies and through phis whose operands are all the same value."""
        assert self._values is not None
        expr = self._values.resolve(expr)
        if isinstance(expr, VirtualVariable):
            src = self._values.defs.get(expr.varid)
            if isinstance(src, Phi):
                ops = {
                    r.varid
                    for _, v in src.src_and_vvars
                    if v is not None and isinstance(r := self._values.resolve(v), VirtualVariable)
                }
                if len(ops) == 1 and all(v is not None for _, v in src.src_and_vvars):
                    return self._values.resolve(next(v for _, v in src.src_and_vvars))
        return expr

    def _pointee_type(self, base: Expression) -> SimType | None:
        assert self._values is not None
        base = self._resolve_phi(base)
        if not isinstance(base, VirtualVariable):
            return None
        ty = self._values.param_types.get(base.varid)
        if ty is None:
            hit = self._values.combo_of.get(base.varid)
            if hit is not None:
                # the pointer word of a fused value: a slice's array or a pointer result
                words = self._combo_words(hit[0])
                if hit[1] < len(words) and words[hit[1]] is not None and words[hit[1]][1] == 0:
                    ty = words[hit[1]][0]
                    if isinstance(ty, GoSimTypeSlice):
                        return ty.elem_type
            else:
                src = self._values.defs.get(base.varid)
                if isinstance(src, Call):
                    proto = self._callee_prototype(src)
                    if proto is not None and len(proto.results) == 1:
                        ty = proto.results[0]
        if isinstance(ty, GoSimTypePointer):
            return ty.pts_to
        return None

    def _is_readonly(self, addr: int) -> bool:
        section = self.project.loader.find_section_containing(addr)
        return section is not None and section.is_readable and not section.is_writable

    #
    # Results, caller side: how this function uses the results of calls to functions with guessed results
    #

    def _infer_caller_results(self) -> None:
        assert self._values is not None
        values = self._values
        sigs = self.kb.go_signatures
        # result values of calls whose results are only guessed: varid of the (combo) vvar -> (record key, words);
        # the key is the callee's name, or the call address of an indirect call GoCallResultBinder bound
        targets: dict[int, tuple[str | int, int]] = {}
        for stmt, call in self._values.calls:
            dst = None
            if isinstance(stmt, Assignment) and isinstance(stmt.dst, VirtualVariable):
                dst = stmt.dst
            elif isinstance(stmt, SideEffectStatement) and isinstance(stmt.ret_expr, VirtualVariable):
                dst = stmt.ret_expr
            if dst is None:
                continue
            target = call.target.value if isinstance(call.target, Const) else None
            key: str | int | None = None
            if isinstance(target, int) and self.kb.functions.contains_addr(target):
                callee = self.kb.functions.get_by_addr(target, meta_only=True)
                if sigs.results_guessed(callee):
                    key = callee.name
            elif not isinstance(call.target, str):
                site = stmt.tags.get("ins_addr")
                if isinstance(site, int) and sigs.callsite_record(site) is not None:
                    key = site
            if key is not None:
                targets[dst.varid] = (key, len(dst.reg_vvars or ()) or 1)
        if not targets:
            return
        found: dict[str | int, Words] = {}
        groups: dict[str | int, dict[int, tuple[int, str | None]]] = {}

        def note_words(expr, type_str: str, span: int, exact: bool = True) -> None:
            piece = self._piece(expr)
            if piece is None:
                return
            varid, word, have = piece
            hit = targets.get(varid)
            if hit is None:
                return
            if exact and have != span:
                # a whole multi-word result handed to a narrower consumer: the consumer takes its first words
                resolved = values.resolve(expr)
                whole = isinstance(resolved, VirtualVariable) and resolved.varid == varid
                if not (whole and word == 0 and have > span):
                    return
                RULE_HITS["prefix"] += 1
            _record(found.setdefault(hit[0], {}), word, type_str, span)

        def note_run(exprs, ty) -> None:
            """Consecutive one-word leaves that together carry one value of type ``ty``."""
            if not isinstance(ty, GoSimType) or not ty.size or go_type_repr(ty) in ("unsafe.Pointer", "uintptr"):
                return
            maybe = [self._piece(e) for e in exprs]
            pieces = [p for p in maybe if p is not None and p[2] == 1]
            if not maybe or len(pieces) != len(maybe):
                return
            varid, word, _ = pieces[0]
            if any(p[0] != varid or p[1] != word + i for i, p in enumerate(pieces)):
                return
            hit = targets.get(varid)
            if hit is not None:
                _record(found.setdefault(hit[0], {}), word, go_type_repr(ty), len(pieces))
                RULE_HITS["run"] += 1

        def note(expr, ty) -> None:
            if isinstance(expr, Call) and expr.tags.get("go_render") == "box" and expr.args:
                # box(value) handed on or returned: the value has the box's concrete type
                note(expr.args[0], self._type_named(expr.tags.get("go_box_type")))
                return
            if not isinstance(ty, GoSimType) or not ty.size:
                return
            repr_ = go_type_repr(ty)
            if repr_ in ("unsafe.Pointer", "uintptr"):
                # an untyped pointer or word says nothing about the value
                return
            if repr_ == "*internal/abi.Type":
                # the type word of an empty interface handed to a runtime helper
                note_words(expr, "any", 2, exact=False)
                return
            note_words(expr, repr_, _leaf_count(ty))

        own = self._func.get_prototype(Flavors.GO_FLAVOR)
        if sigs.results_guessed(self._func):
            # the result types this pass just inferred from the returns apply only on the next decompilation; use
            # them now so a returned call result is typed in the same pass
            own = sigs.inferred_prototype(self._func.name, own) or own
        for block in self._graph.nodes:
            for stmt in block.statements:
                if isinstance(stmt, Return) and stmt.ret_exprs and isinstance(own, GoSimTypeFunction):
                    self._note_return(stmt, own, note, note_run)
                elif isinstance(stmt, Store):
                    base, off = _addr_base_and_offset(stmt.addr)
                    pointee = self._pointee_type(base) if base is not None else None
                    if isinstance(pointee, GoSimStruct):
                        note(stmt.data, _field_at(pointee, off))
                elif isinstance(stmt, ConditionalJump):
                    self._note_compare(stmt.condition, note_words)
        for call in self._values.all_calls:
            if not call.args:
                continue
            if call.tags.get("go_render") == "box":
                note(call, None)
                continue
            proto = self._callee_prototype(call)
            if proto is None or _converts_arguments(call_target_name(self.project, call)):
                continue
            if len(call.args) == len(proto.args):
                for arg, ty in zip(call.args, proto.args):
                    note(arg, ty)
            else:
                # arguments passed word by word: align them with the parameters' words
                _note_leaves(list(call.args), _value_words(list(proto.args)), note, note_run)

        # the shapes of the reads: interface pairs (2a), empty-interface pairs (2b), fused multi-word reads (2c)
        evidence = _ResultEvidence(self, targets)
        for block in self._graph.nodes:
            evidence.walk(block)
        for (varid, w), flags in evidence.flags.items():
            key, nwords = targets[varid]
            if "eface" in flags:
                _record(found.setdefault(key, {}), w, "any", 2)
                RULE_HITS["2b"] += 1
            elif _is_interface_pair(flags):
                # Go puts the error last; another interface pair stays an untyped group
                if w + 2 == nwords:
                    _record(found.setdefault(key, {}), w, "error", 2)
                else:
                    groups.setdefault(key, {})[w] = (2, None)
                RULE_HITS["2a"] += 1
        for varid, w, n in sorted(evidence.spans):
            key, _ = targets[varid]
            if w in found.get(key, {}):
                continue
            name = evidence.span_names.get((varid, w, n))
            if (name is None and n == 2 and "string" in evidence.flags.get((varid, w), ())) or (
                name is None and n == 2 and "len" in evidence.flags.get((varid, w + 1), ())
            ):
                name = "string"
            elif name is None and n == 3 and "len" in evidence.flags.get((varid, w + 1), ()):
                name = "[]uintptr"
            if name is not None:
                _record(found.setdefault(key, {}), w, name, n)
            else:
                groups.setdefault(key, {}).setdefault(w, (n, None))
            RULE_HITS["2c"] += 1

        for key in set(found) | set(groups):
            words, grouped = found.get(key), groups.get(key)
            if isinstance(key, int):
                sigs.set_callsite_inferred(key, caller_results=words, groups=grouped)
                l.debug("Inferred results of the call at %#x in %s: %s %s", key, self._func.name, words, grouped)
            else:
                sigs.set_inferred(key, caller_results=words, groups=grouped)
                l.debug("Inferred results of %s from its caller %s: %s %s", key, self._func.name, words, grouped)

    @staticmethod
    def _note_return(stmt: Return, proto: GoSimTypeFunction, note, note_run) -> None:
        results = proto.results
        exprs = list(stmt.ret_exprs)
        if len(exprs) == len(results):
            for expr, ty in zip(exprs, results):
                note(expr, ty)
            return
        # unfused: one leaf per word
        _note_leaves(exprs, _result_words(proto), note, note_run)

    def _note_compare(self, cond: Expression, note_words) -> None:
        """``x == &go:itab.T,I``: the word compared is the itab of an ``I`` value, the next word its data."""
        if not isinstance(cond, BinaryOp) or cond.op not in ("CmpEQ", "CmpNE"):
            return
        a, b = cond.operands
        for x, y in ((a, b), (b, a)):
            if isinstance(y, Const) and y.is_int:
                itab = self.kb.go_types.itab_at(y.value_int)
                if itab is not None:
                    note_words(x, itab[0], 2, exact=False)

    def _piece(self, expr: Expression) -> tuple[int, int, int] | None:
        """(varid of the call result, first word, words) an expression covers of a call result value."""
        assert self._values is not None
        bytes_ = self.project.arch.bytes
        expr = self._values.resolve(expr)
        if isinstance(expr, VirtualVariable):
            hit = self._values.combo_of.get(expr.varid)
            if hit is not None:
                return hit[0].varid, hit[1], 1
            if expr.reg_vvars:
                return expr.varid, 0, len(expr.reg_vvars)
            src = self._values.defs.get(expr.varid)
            if isinstance(src, (Load, Extract)):
                # a word (or words) of a result copied into a register
                piece = self._piece(src)
                if piece is not None:
                    return piece
            return expr.varid, 0, 1
        if isinstance(expr, Load):
            addr = expr.addr
            off = 0
            if isinstance(addr, BinaryOp) and addr.op == "Add" and isinstance(addr.operands[1], Const):
                off = addr.operands[1].value_int
                addr = addr.operands[0]
            if isinstance(addr, UnaryOp) and addr.op == "Reference" and isinstance(addr.operand, VirtualVariable):
                combo = addr.operand
                if combo.reg_vvars and off % bytes_ == 0 and expr.size % bytes_ == 0:
                    return combo.varid, off // bytes_, expr.size // bytes_
            return None
        if isinstance(expr, Extract):
            # words of a combo read as one value (an interface pair handed to a box)
            base, off = expr.base, expr.offset
            if (
                isinstance(base, VirtualVariable)
                and base.reg_vvars
                and isinstance(off, Const)
                and off.value_int % bytes_ == 0
                and expr.size % bytes_ == 0
            ):
                return base.varid, off.value_int // bytes_, expr.size // bytes_
            return None
        if isinstance(expr, Struct):
            maybe = [self._piece(expr.fields[off]) for off in sorted(expr.fields)]
            pieces = [p for p in maybe if p is not None]
            if not maybe or len(pieces) != len(maybe):
                return None
            varid, word, _ = pieces[0]
            expected = word
            for p in pieces:
                if p[0] != varid or p[1] != expected:
                    return None
                expected += p[2]
            return varid, word, expected - word
        return None

    #
    # Cleanup: drop the result words the widener added beyond the guessed prototype
    #

    def _trim_returns(self) -> None:
        changed = False
        for block in self._graph.nodes:
            for idx, stmt in enumerate(block.statements):
                if isinstance(stmt, Return) and RET_FLOOR_TAG in stmt.tags:
                    tags = dict(stmt.tags)
                    floor = tags.pop(RET_FLOOR_TAG)
                    block.statements[idx] = Return(stmt.idx, list(stmt.ret_exprs)[:floor], **tags)
                    changed = True
        if not changed:
            return
        # definitions only the dropped words used are dead now
        while True:
            collector = VVarUsesCollector()
            for block in self._graph.nodes:
                collector.walk(block)
            used = collector.vvars
            removed = False
            for block in self._graph.nodes:
                keep = []
                for stmt in block.statements:
                    if (
                        isinstance(stmt, Assignment)
                        and isinstance(stmt.dst, VirtualVariable)
                        and stmt.dst.varid not in used
                        and not isinstance(stmt.src, Call)
                        and not any(rv.varid in used for rv in stmt.dst.reg_vvars or [])
                    ):
                        removed = True
                        continue
                    keep.append(stmt)
                if len(keep) != len(block.statements):
                    block.statements = keep
            if not removed:
                break
        self.out_graph = self._graph


class _Values:
    """Definitions and register pieces of the function's virtual variables."""

    def __init__(self, pass_: GoPrototypeInference):
        self.defs: dict[int, Expression] = {}
        self.combo_of: dict[int, tuple[VirtualVariable, int]] = {}
        self.param_types: dict[int, SimType] = {}
        self.calls: list[tuple[Statement, Call]] = []
        self.all_calls: list[Call] = []  # every call, nested ones included (a folded append inside a return)
        bytes_ = pass_.project.arch.bytes

        def note(vvar: VirtualVariable):
            is_combo = vvar.category == VVC.COMBO_REGISTER or (
                vvar.category == VVC.PARAMETER and vvar.parameter_category == VVC.COMBO_REGISTER
            )
            if is_combo and vvar.reg_vvars:
                offset = 0
                for reg_vvar in vvar.reg_vvars:
                    self.combo_of[reg_vvar.varid] = (vvar, offset // bytes_)
                    offset += reg_vvar.size

        proto = pass_._func.get_prototype(Flavors.GO_FLAVOR)
        if pass_._arg_vvars:
            args = list(proto.args) if isinstance(proto, GoSimTypeFunction) else []
            for i, (arg_vvar, _) in sorted(pass_._arg_vvars.items(), key=lambda kv: kv[0]):
                if isinstance(arg_vvar, VirtualVariable):
                    note(arg_vvar)
                    if i < len(args):
                        self.param_types[arg_vvar.varid] = args[i]
        collector = _CallCollector()
        for block in pass_._graph.nodes:
            collector.walk(block)
            for stmt in block.statements:
                if isinstance(stmt, Assignment) and isinstance(stmt.dst, VirtualVariable):
                    note(stmt.dst)
                    self.defs[stmt.dst.varid] = stmt.src
                    if isinstance(stmt.src, Call):
                        self.calls.append((stmt, stmt.src))
                elif isinstance(stmt, SideEffectStatement) and isinstance(stmt.expr, Call):
                    self.calls.append((stmt, stmt.expr))
                    if isinstance(stmt.ret_expr, VirtualVariable):
                        note(stmt.ret_expr)
                        self.defs[stmt.ret_expr.varid] = stmt.expr
        self.all_calls = collector.calls

    def resolve(self, expr: Expression) -> Expression:
        """Look through virtual-variable copies."""
        seen = set()
        while isinstance(expr, VirtualVariable) and expr.varid not in seen:
            seen.add(expr.varid)
            src = self.defs.get(expr.varid)
            if not isinstance(src, VirtualVariable):
                break
            expr = src
        return expr


class _CallCollector(AILBlockViewer):
    def __init__(self):
        super().__init__()
        self.calls: list[Call] = []

    def _handle_Call(self, expr_idx, expr: Call, stmt_idx, stmt, block):
        self.calls.append(expr)
        super()._handle_Call(expr_idx, expr, stmt_idx, stmt, block)


class _ResultEvidence(AILBlockViewer):
    """
    The shapes of the reads of guessed call results, per (result varid, word): ``nil`` (compared with 0), ``eface``
    (compared with a type descriptor or handed to an eface helper), ``itab`` (compared with an itab), ``typeload``
    (the nil-guarded ``Load(w + ws)`` of an iface-to-eface conversion), ``method`` (a call through ``w``'s method
    table), ``helper`` (handed to an iface runtime helper), ``boxed`` (the pair boxed as a whole), ``len`` (bounded
    against another value or handed to a string helper). ``spans`` are fused reads of several words.
    """

    def __init__(self, pass_: GoPrototypeInference, targets: dict):
        super().__init__()
        self._pass = pass_
        self._targets = targets
        self._ws = pass_.project.arch.bytes
        self._fun_offset = -(-(2 * self._ws + 4) // self._ws) * self._ws
        self.flags: dict[tuple[int, int], set[str]] = defaultdict(set)
        self.spans: set[tuple[int, int, int]] = set()
        self.span_names: dict[tuple[int, int, int], str] = {}

    def _piece(self, expr, words: int | None = None) -> tuple[int, int] | None:
        piece = self._pass._piece(expr)
        if piece is None or piece[0] not in self._targets or (words is not None and piece[2] != words):
            return None
        return piece[0], piece[1]

    def _note_span(self, expr) -> None:
        piece = self._pass._piece(expr)
        if piece is None or piece[2] < 2 or piece[0] not in self._targets:
            return
        if piece[2] < self._targets[piece[0]][1]:
            self.spans.add(piece)
            if isinstance(expr, Struct) and (expr.name == "string" or expr.name.startswith("[]")):
                self.span_names[piece] = expr.name

    def _handle_Load(self, expr_idx, expr, stmt_idx, stmt, block):
        self._note_span(expr)
        super()._handle_Load(expr_idx, expr, stmt_idx, stmt, block)

    def _handle_Extract(self, expr_idx, expr, stmt_idx, stmt, block):
        self._note_span(expr)
        super()._handle_Extract(expr_idx, expr, stmt_idx, stmt, block)

    def _handle_Struct(self, expr_idx, expr, stmt_idx, stmt, block):
        self._note_span(expr)
        super()._handle_Struct(expr_idx, expr, stmt_idx, stmt, block)

    def _enter_expr(self, expr_idx, expr, stmt_idx, stmt, block):
        if not isinstance(expr, BinaryOp):
            return super()._enter_expr(expr_idx, expr, stmt_idx, stmt, block)
        a, b = expr.operands
        if expr.op in ("CmpEQ", "CmpNE"):
            for x, y in ((a, b), (b, a)):
                if not (isinstance(y, Const) and y.is_int):
                    continue
                w = self._piece(x, 1)
                if w is None:
                    continue
                if y.value_int == 0:
                    self.flags[w].add("nil")
                elif self._pass.kb.go_types.itab_at(y.value_int) is not None:
                    self.flags[w].add("itab")
                elif go_type_name_at(self._pass.project, y.value_int) is not None:
                    self.flags[w].add("eface")
        elif expr.op.startswith("Cmp") and not isinstance(a, Const) and not isinstance(b, Const):
            for x in (a, b):
                w = self._piece(x, 1)
                if w is not None:
                    self.flags[w].add("len")
        return super()._enter_expr(expr_idx, expr, stmt_idx, stmt, block)

    def _type_load(self, expr) -> tuple[int, int] | None:
        """The word ``w`` when ``expr`` is ``Load(w + ws)`` (an itab's type descriptor)."""
        values = cast(_Values, self._pass._values)  # set before the evidence walk
        expr = values.resolve(expr)
        if isinstance(expr, VirtualVariable):
            expr = values.defs.get(expr.varid, expr)
        if not (isinstance(expr, Load) and expr.size == self._ws):
            return None
        base, off = _addr_base_and_offset(expr.addr)
        return self._piece(base, 1) if base is not None and off == self._ws else None

    def _handle_ITE(self, expr_idx, expr, stmt_idx, stmt, block):
        cond = expr.cond
        if isinstance(cond, BinaryOp) and cond.op in ("CmpEQ", "CmpNE"):
            nil_side, load_side = (expr.iftrue, expr.iffalse) if cond.op == "CmpEQ" else (expr.iffalse, expr.iftrue)
            if isinstance(nil_side, Const) and nil_side.value_int == 0:
                w = self._type_load(load_side)
                if w is not None:
                    self.flags[w].update(("nil", "typeload"))
        super()._handle_ITE(expr_idx, expr, stmt_idx, stmt, block)

    def _handle_Phi(self, expr_idx, expr, stmt_idx, stmt, block):
        sources = [v for _, v in expr.src_and_vvars if v is not None]
        if len(sources) == 2:
            for load_side, other in ((sources[0], sources[1]), (sources[1], sources[0])):
                w = self._type_load(load_side)
                if w is None:
                    continue
                other = cast(_Values, self._pass._values).resolve(other)
                if (isinstance(other, Const) and other.value_int == 0) or self._piece(other, 1) == w:
                    self.flags[w].update(("nil", "typeload"))
        super()._handle_Phi(expr_idx, expr, stmt_idx, stmt, block)

    def _handle_Call(self, expr_idx, expr, stmt_idx, stmt, block):
        args = list(expr.args or ())
        if expr.tags.get("go_render") == "box" and expr.tags.get("go_box_type") is None and args:
            # an interface value converted to another interface as a whole
            w = self._piece(args[0], 2)
            if w is not None:
                self.flags[w].add("boxed")
        target = expr.target
        if isinstance(target, Load):
            base, off = _addr_base_and_offset(target.addr)
            if base is not None and off >= self._fun_offset and (off - self._fun_offset) % self._ws == 0:
                w = self._piece(base, 1)
                if w is not None:
                    self.flags[w].add("method")
        name = call_target_name(self._pass.project, expr)
        name = normalize_go_func_name(name) if name else None
        if name in _IFACE_HELPERS or name in _EFACE_HELPERS or name in _LENGTH_HELPERS:
            flag = "helper" if name in _IFACE_HELPERS else "eface" if name in _EFACE_HELPERS else "len"
            for arg in args:
                w = self._piece(arg, 1 if flag == "len" else 2)
                if w is not None:
                    self.flags[w].add(flag)
        if name in _STRING_HELPERS:
            for arg in args:
                w = self._piece(arg, 2)
                if w is not None:
                    self.flags[w].add("string")
        super()._handle_Call(expr_idx, expr, stmt_idx, stmt, block)


def _is_interface_pair(flags: set[str]) -> bool:
    """
    A nil-checked word is an itab only with a second witness: a bare nil check plus ``Load(w + ws)`` is also what a
    ``(*T, n)`` result looks like.
    """
    return "nil" in flags and bool(flags & _IFACE_FLAGS)


def _converts_arguments(name: str | None) -> bool:
    """Runtime helpers whose parameter types say nothing about the caller's value (``printint(int64(n))``)."""
    if name is None:
        return False
    name = normalize_go_func_name(name)
    return name.startswith("runtime.print") or (
        name.startswith("runtime.convT") and name not in ("runtime.convTstring", "runtime.convTslice")
    )


def _record(found: dict, word: int, type_str: str, span: int) -> None:
    # a conflicting earlier guess wins only if it is wider (an interface over its first word as an int)
    old = found.get(word)
    if old is None or old[1] < span:
        found[word] = (type_str, span)


def _note_leaves(exprs: list, words: list, note, note_run) -> None:
    """One leaf per value word: a multi-word value's leaves are noted as a run, a one-word value's leaf alone."""
    for i, word in enumerate(words[: len(exprs)]):
        if word is None or word[1] != 0:
            continue
        ty, _, n = word
        if n > 1 and i + n <= len(exprs):
            note_run(exprs[i : i + n], ty)
        note(exprs[i], ty)


def _value_words(types: list) -> list[tuple[SimType, int, int] | None]:
    """Per register word of the values: (type, word within that type, words of that type); None for non-Go types."""
    words: list = []
    for ty in types:
        if not isinstance(ty, GoSimType) or not ty.size:
            words.append(None)
            continue
        n = _leaf_count(ty)
        words.extend((ty, k, n) for k in range(n))
    return words


def _untyped_slice_header(words: list) -> bool:
    """Three result words spelling a slice header without its element type (``runtime.slice`` or its fields)."""
    if any(w is None for w in words):
        return False
    reprs = [go_type_repr(w[0]) for w in words]
    return reprs in (["runtime.slice"] * 3, ["unsafe.Pointer", "int", "int"])


def _result_words(proto: GoSimTypeFunction) -> list[tuple[SimType, int, int] | None]:
    return _value_words(proto.results)


def _addr_base_and_offset(addr: Expression) -> tuple[Expression | None, int]:
    """``base + k`` -> (base, k); ``Const c`` -> (None, c)."""
    if isinstance(addr, Const):
        return None, addr.value_int
    if isinstance(addr, BinaryOp) and addr.op == "Add" and isinstance(addr.operands[1], Const):
        return addr.operands[0], addr.operands[1].value_int
    if isinstance(addr, BinaryOp) and addr.op == "Add" and isinstance(addr.operands[0], Const):
        return addr.operands[1], addr.operands[0].value_int
    return addr, 0


def _scalar_fields(struct: GoSimStruct, base: int) -> list[tuple[int, int] | None]:
    """(byte offset, byte size) of every scalar leaf of ``struct``, in order; None where the layout is unknown."""
    out: list = []
    for name, ty in struct.fields.items():
        foff = struct.offsets.get(name)
        if foff is None or not ty.size:
            out.append(None)
        elif isinstance(ty, GoSimStruct):
            out.extend(_scalar_fields(ty, base + foff))
        else:
            out.append((base + foff, ty.size // 8))
    return out


def _field_at(struct: GoSimStruct, off: int) -> SimType | None:
    for name, ty in struct.fields.items():
        foff = struct.offsets.get(name)
        if foff == off:
            return ty
        if foff is not None and isinstance(ty, GoSimStruct) and ty.size and foff < off < foff + ty.size // 8:
            inner = _field_at(ty, off - foff)
            if inner is not None:
                return inner
    return None
