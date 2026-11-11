from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from cle import SymbolType

from angr import ailment
from angr.ailment import Assignment
from angr.analyses.typehoon import typevars
from angr.sim_type import (
    SimStruct,
    SimType,
    SimTypeBottom,
    SimTypeChar,
    SimTypeFunction,
    SimTypeInt,
    SimTypeLongLong,
    SimTypeNum,
    SimTypePointer,
    SimTypeShort,
    TypeRef,
)
from angr.sim_variable import SimMemoryVariable, SimStackVariable

from .struct_union import pointer_to_layout, union_pointer_struct_types

if TYPE_CHECKING:
    from angr import Project
    from angr.knowledge_base import KnowledgeBase
    from angr.knowledge_plugins.functions import Function
    from angr.knowledge_plugins.variables.variable_manager import VariableManagerInternal


@dataclass
class CrossFunctionInferenceState:
    """Evidence for one flavor, shared across functions and discarded on KB copy or serialization.

    Own and downward layouts exclude evidence pushed by callers. Local evidence is keyed by
    function and SSA id; global evidence is keyed by ("global", address). Weak layouts retain
    raw access offsets and are kept alive in the cache so their identity remains stable.
    """

    own_arg_layouts: dict[tuple[int, int], SimType] = field(default_factory=dict)
    own_local_layouts: dict[tuple[int, int] | tuple[str, int], list[SimType]] = field(default_factory=dict)
    pushed_arg_unions: dict[tuple[int, int], SimTypePointer] = field(default_factory=dict)
    arg_downward_evidence: dict[tuple[int, int], list[SimType]] = field(default_factory=dict)
    global_union_contributors: dict[int, set[tuple[int, int]]] = field(default_factory=dict)
    union_struct_evidence: dict[str, list[SimType]] = field(default_factory=dict)
    arg_accessed_fields: dict[tuple[int, int], dict[int, int]] = field(default_factory=dict)
    arg_forward_targets: dict[tuple[int, int], set[tuple[int, int]]] = field(default_factory=dict)
    arg_typed_sink_uses: set[tuple[int, int]] = field(default_factory=set)
    weak_layouts: set[int] = field(default_factory=set)
    weak_layout_cache: dict[tuple, SimTypePointer] = field(default_factory=dict)
    union_struct_layouts: dict[tuple, str] = field(default_factory=dict)


class CrossFunctionTypeInference:
    """Merge direct layout evidence and propagate compatible argument types between functions.

    A short-lived instance supplies the current function context; all accumulated evidence
    lives in a typed state owned by the KB's type store and isolated by flavor.
    """

    def __init__(self, project: Project, kb: KnowledgeBase, function: Function, flavor: str):
        self.project = project
        self.kb = kb
        self.function = function
        self.flavor = flavor
        states = kb.types._cross_function_inference  # pylint:disable=protected-access
        if flavor not in states:
            states[flavor] = CrossFunctionInferenceState()
        self._state = states[flavor]

    @staticmethod
    def _pointee_struct(ty) -> SimStruct | None:
        """Return the struct a pointer points to (resolving TypeRefs), or None if it is not a pointer-to-struct."""
        if not isinstance(ty, SimTypePointer):
            return None
        pts_to = ty.pts_to
        seen = set()
        while isinstance(pts_to, TypeRef) and id(pts_to) not in seen:
            seen.add(id(pts_to))
            pts_to = pts_to.ty
        return pts_to if isinstance(pts_to, SimStruct) else None

    @staticmethod
    def _struct_of(ty) -> SimStruct | None:
        """Return the struct a (possibly TypeRef-wrapped) type denotes by value, or None."""
        seen = set()
        while isinstance(ty, TypeRef) and id(ty) not in seen:
            seen.add(id(ty))
            ty = ty.ty
        return ty if isinstance(ty, SimStruct) else None

    def _global_object_view(self, variable, current) -> bool:
        """
        Whether ``current`` is this function's view of a global *object* (accessed by value): a struct, or a scalar
        narrower than the object, which is then the member at offset 0 (a function that only touches the first
        member sees the whole object as that scalar).
        """
        if current is None or isinstance(current, SimTypePointer):
            return False
        if self._struct_of(current) is not None:
            return True
        size = getattr(variable, "size", None)
        try:
            width = current.size // self.project.arch.byte_width if current.size else None
        except Exception:  # pylint:disable=broad-except
            return False
        return width is not None and size is not None and size > width

    @staticmethod
    def _real_field_count(struct: SimStruct) -> int:
        """Number of fields that are not padding. ``SimStruct.offsets`` counts padding entries too, which must not be
        mistaken for evidence of a struct."""
        return sum(1 for name in struct.fields if not name.startswith("padding_"))

    @staticmethod
    def _struct_layout_signature(struct: SimStruct) -> tuple | None:
        """A name-independent signature of a struct's field layout, used to deduplicate identical layouts."""
        try:
            offsets = struct.offsets
            sig = tuple(
                sorted(
                    (offset, fld_ty.c_repr() if hasattr(fld_ty, "c_repr") else repr(fld_ty))
                    for fld_name, fld_ty in struct.fields.items()
                    if not fld_name.startswith("padding_") and (offset := offsets.get(fld_name)) is not None
                )
            )
        except Exception:  # pylint:disable=broad-except
            return None
        return sig or None

    def pushed_union_for_argument(self, arg_idx: int) -> SimTypePointer | None:
        """The union callers pushed into this function's argument, if it still covers the function's own layout."""
        pushed = self._state.pushed_arg_unions.get((self.function.addr, arg_idx))
        if pushed is None:
            return None
        union_struct = self._pointee_struct(pushed)
        if union_struct is None or not self._is_minted_union_type(pushed):
            return None
        if not self._covers_own_layout(union_struct, self.function.addr, arg_idx):
            return None
        accessed = self._state.arg_accessed_fields.get((self.function.addr, arg_idx))
        if accessed and not self._union_covers_accesses(union_struct, accessed):
            return None
        return pushed

    def _global_manager(self):
        return self.kb.dec_variables.get_global_manager(self.flavor)

    @staticmethod
    def _is_global_variable(variable) -> bool:
        return isinstance(variable, SimMemoryVariable) and not isinstance(variable, SimStackVariable)

    def _global_content_observations(self, observations) -> dict:
        """
        Observations keyed by the *content* of a global rather than by the global itself: an argument that is a load
        from a global pointer carries the type variable ``base.load.<ptr bits>@0``, while variable recovery maps the
        global variable to ``base``. Return a map from the base type variable to those observations.
        """
        out: dict = {}
        bits = self.project.arch.bits
        for tv, obs in observations.items():
            if not isinstance(tv, typevars.DerivedTypeVariable) or len(tv.labels) != 2:
                continue
            load, field = tv.labels
            if (
                isinstance(load, typevars.Load)
                and isinstance(field, typevars.HasField)
                and field.offset == 0
                and field.bits == bits
            ):
                out.setdefault(tv.type_var, []).extend(obs)
        return out

    def _minted_union_struct_names(self) -> set[str]:
        registry: dict[tuple, str] = self._state.union_struct_layouts
        return set(registry.values())

    def _expand_union_evidence(self, ty) -> list[SimType]:
        """The direct layouts behind a minted union struct type (empty when the struct has no recorded provenance)."""
        struct = self._pointee_struct(ty)
        if struct is None:
            inner = ty.ty if isinstance(ty, TypeRef) else ty
            struct = inner if isinstance(inner, SimStruct) else None
        if struct is None:
            return []
        return list(self._state.union_struct_evidence.get(struct._name, ()))  # pylint:disable=protected-access

    def _is_minted_union_type(self, ty) -> bool:
        """Whether a (pointer-to-)struct type is one of the union structs minted by this decompiler session."""
        struct = self._pointee_struct(ty)
        if struct is None:
            inner = ty.ty if isinstance(ty, TypeRef) else ty
            struct = inner if isinstance(inner, SimStruct) else None
        return struct is not None and struct._name in self._minted_union_struct_names()  # pylint:disable=protected-access

    def record_own_argument_layouts(self, arg_vvars, var_manager, vr=None) -> None:
        """
        Record, for each argument, the type this function's own accesses gave it. An argument whose type was pinned to
        a struct pointer through the prototype (a back-propagated union or a call-site constraint) carries no evidence
        of its own, so an earlier record for it is kept and nothing new is written.

        When the argument was solved as a pointer to a scalar (or an array of scalars) although the function accessed
        it at constant offsets other than 0 (``a->x * a->y`` reads the same as ``a[4] * a[5]``), the solved type has
        lost those offsets and would join a union as a member at offset 0. The record is then a layout of the accessed
        offsets instead, marked weak (see :attr:`CrossFunctionInferenceState.weak_layouts`).
        """
        if not arg_vvars:
            return
        proto = self.function.get_prototype(self.flavor)
        pinned = proto is not None and self.function.is_prototype_groundtruth_for(self.flavor)
        for arg_idx, (_, variable) in arg_vvars.items():
            if vr is not None:
                # the offsets the function's own code touches, whatever type the argument was pinned to
                accessed = self._accessed_fields(vr, variable)
                if accessed is None:
                    self._state.arg_accessed_fields.pop((self.function.addr, arg_idx), None)
                else:
                    self._state.arg_accessed_fields[(self.function.addr, arg_idx)] = accessed
                if any(tv in vr.arg_typed_sink_typevars for tv in vr.var_to_typevars.get(variable, ())):
                    self._state.arg_typed_sink_uses.add((self.function.addr, arg_idx))
                else:
                    self._state.arg_typed_sink_uses.discard((self.function.addr, arg_idx))
            if pinned and arg_idx < len(proto.args) and self._pointee_struct(proto.args[arg_idx]) is not None:
                continue
            if self.pushed_union_for_argument(arg_idx) is not None:
                continue
            ty = var_manager.get_variable_type(variable)
            if ty is None or self._is_minted_union_type(ty):
                continue
            if vr is not None and self._pointee_struct(ty) is None:
                accessed = self._accessed_member_layout(vr, variable)
                if accessed is not None:
                    ty = accessed
            self._state.own_arg_layouts[(self.function.addr, arg_idx)] = ty

    @staticmethod
    def _accessed_fields(vr, variable) -> dict[int, int] | None:
        """
        The constant offsets (and the widest access in bits at each) at which this function loads from or stores to
        the pointer or object held in ``variable``, or None when it is indexed with a variable anywhere (an array).
        """
        tvs = set(vr.var_to_typevars.get(variable, ()))
        fields: dict[int, int] = {}
        if not tvs:
            return fields
        for constraints in vr.type_constraints.values():
            for constraint in constraints:
                for side in (getattr(constraint, "sub_type", None), getattr(constraint, "super_type", None)):
                    if not isinstance(side, typevars.DerivedTypeVariable) or side.type_var not in tvs:
                        continue
                    if any(isinstance(label, typevars.IsArray) for label in side.labels):
                        # indexed with a variable somewhere: this is an array, not a struct read as one
                        return None
                    if len(side.labels) != 2:
                        continue
                    access, field = side.labels
                    if not isinstance(access, (typevars.Load, typevars.Store)) or not isinstance(
                        field, typevars.HasField
                    ):
                        continue
                    if field.offset is None or field.bits is None or field.bits % 8 or field.bits > 64:
                        continue
                    fields[field.offset] = max(fields.get(field.offset, 0), field.bits)
        return fields

    def _accessed_member_layout(self, vr, variable) -> SimTypePointer | None:
        """
        A weak layout of the constant offsets at which this function loads from or stores to the pointer held in
        ``variable``, or None when it touches nothing but offset 0 (a plain ``*p``) or indexes it as an array.
        """
        fields = self._accessed_fields(vr, variable)
        if not fields or not any(offset != 0 for offset in fields):
            return None
        return self._weak_layout(fields)

    def _weak_layout(self, fields: dict[int, int]) -> SimTypePointer:
        """A weak layout (see :attr:`CrossFunctionInferenceState.weak_layouts`) of the given offset -> access width in bits."""
        # one object per distinct layout, so that repeated decompilations do not pile up copies in the records
        key = tuple(sorted(fields.items()))
        cache = self._state.weak_layout_cache
        ptr = cache.get(key)
        if ptr is None:
            sized = {8: SimTypeChar, 16: SimTypeShort, 32: SimTypeInt, 64: SimTypeLongLong}
            layout = {
                offset: (sized[bits](signed=False) if bits in sized else SimTypeNum(bits, signed=False)).with_arch(
                    self.project.arch
                )
                for offset, bits in key
            }
            ptr = pointer_to_layout(layout, self.project.arch)
            cache[key] = ptr
            self._state.weak_layouts.add(id(ptr))
        return ptr

    def _covers_own_layout(self, union_struct: SimStruct, func_addr: int, arg_idx: int) -> bool:
        """
        Whether a union keeps everything a function's own layout for an argument established. A layout Typehoon solved
        as a struct needs each of its members at the same offset with at least its size. A weak layout is only the
        offsets the function touched, so it only needs each of them to land inside a member: the union may well have
        merged two of them into one wider member.
        """
        own = self._state.own_arg_layouts.get((func_addr, arg_idx))
        own_struct = self._pointee_struct(own)
        if own_struct is None:
            return True
        if id(own) not in self._state.weak_layouts:
            return self._layout_covers(union_struct, own_struct)
        offsets = own_struct.offsets
        accessed = {
            offsets[name]: (fld_ty.size or 8)
            for name, fld_ty in own_struct.fields.items()
            if not name.startswith("padding_") and name in offsets
        }
        return self._union_covers_accesses(union_struct, accessed)

    def _has_struct_evidence(self, func_addr: int, arg_idx: int, seen: set[tuple[int, int]] | None = None) -> bool:
        """
        Whether a function dereferences the argument at a constant offset or hands it to a typed pointer parameter of a
        fixed prototype (strcmp's char *), itself or through the callees it passes the argument on to. One that only
        hands it to memcpy's void *, or was not decompiled yet, may be receiving any object.
        """
        key = (func_addr, arg_idx)
        if self._state.arg_accessed_fields.get(key) or key in self._state.arg_typed_sink_uses:
            return True
        if seen is None:
            seen = set()
        if key in seen:
            return False
        seen.add(key)
        return any(self._has_struct_evidence(f, i, seen) for f, i in self._state.arg_forward_targets.get(key, ()))

    @staticmethod
    def _union_covers_accesses(union_struct: SimStruct, accessed: dict[int, int]) -> bool:
        """Whether every accessed (offset, bits) lies inside one non-padding member of ``union_struct``."""
        spans = []
        offsets = union_struct.offsets
        for name, fld_ty in union_struct.fields.items():
            if name.startswith("padding_") or name not in offsets:
                continue
            try:
                size = fld_ty.size // 8 if fld_ty.size else 1
            except Exception:  # pylint:disable=broad-except
                size = 1
            spans.append((offsets[name], offsets[name] + size))
        return all(any(lo <= off and off + bits // 8 <= hi for lo, hi in spans) for off, bits in accessed.items())

    def _contributor_evidence(self, callee_addr: int, arg_idx: int, observed: SimType) -> list[SimType]:
        """
        The layouts a callee argument contributes to a union: what the callee and, transitively, its own callees
        learned about that argument when the callee was decompiled (see :attr:`CrossFunctionInferenceState.arg_downward_evidence`); without such
        a record, the callee's own recorded layout, and otherwise the type observed at the call site, expanded into
        its provenance when it is itself a union struct.

        Only evidence gathered below the callee is used. The callee's prototype may carry a union pushed into it by
        some other caller, which is about that caller's object; reading it here would carry one caller's struct into
        another's.
        """
        down = self._state.arg_downward_evidence.get((callee_addr, arg_idx))
        if down:
            evidence = list(down)
        else:
            own = self._state.own_arg_layouts.get((callee_addr, arg_idx))
            if own is not None:
                evidence = [own]
            elif self._is_minted_union_type(observed):
                evidence = self._expand_union_evidence(observed)
            else:
                evidence = [observed]
        # the offsets the callee's own code touches, recorded whatever its argument was pinned to: a union built
        # without them could not be pushed back into the callee without hiding one of its accesses
        accessed = self._state.arg_accessed_fields.get((callee_addr, arg_idx))
        if accessed:
            weak = self._weak_layout(accessed)
            if all(x is not weak for x in evidence):
                evidence.append(weak)
        return evidence

    def _caller_evidence(self, variable, current, arg_vvars, contaminated: set[int]) -> list[SimType]:
        """
        The layouts the caller's own accesses give a value. For the caller's own arguments this is the recorded own
        layout, plus the provenance of a union struct the function's callers pushed into its prototype for that
        argument (the callers saw the same object, so what they assembled is evidence about it and has to reach the
        callees this function passes the argument on to). For a local already typed as a union struct it is that
        struct's provenance. For any other local it is the inferred type minus any field that a union struct among the
        callee prototypes already carried, because Typehoon copies callee prototype layouts into the locals passed to
        them.
        """
        if arg_vvars:
            for arg_idx, (_, arg_var) in arg_vvars.items():
                if arg_var is variable:
                    evidence = []
                    own = self._state.own_arg_layouts.get((self.function.addr, arg_idx))
                    if own is not None:
                        evidence.append(own)
                    # the union pushed from above is pinned on the argument (its solved type) and recorded in the
                    # pushed-union table; the prototype itself is recomputed when the decompilation starts
                    known = {id(x) for x in evidence}
                    for pushed in (current, self.pushed_union_for_argument(arg_idx)):
                        if pushed is None or not self._is_minted_union_type(pushed):
                            continue
                        for layout in self._expand_union_evidence(pushed):
                            if id(layout) not in known:
                                evidence.append(layout)
                                known.add(id(layout))
                    return evidence
        if not isinstance(current, SimTypePointer):
            return []
        if self._is_minted_union_type(current):
            return self._expand_union_evidence(current)
        struct = self._pointee_struct(current)
        if struct is None or not contaminated:
            return [current]
        offsets = struct.offsets
        kept: dict[int, SimType] = {}
        for fld_name, fld_ty in struct.fields.items():
            if fld_name.startswith("padding_"):
                continue
            offset = offsets.get(fld_name)
            if offset is None or offset in contaminated:
                continue
            kept[offset] = fld_ty
        if not kept:
            return []
        return [pointer_to_layout(kept, self.project.arch)]

    def _sanitize_union_struct_fields(self, union_struct: SimStruct) -> None:
        """
        Replace pointer-to-struct fields with ``void *`` unless they point to a struct minted by union
        canonicalization. Field types are copied from callee prototype structs, whose nested struct references carry
        per-function type names (struct_0, struct_1, ...); importing those into another function's output collides
        with that function's own per-function names.
        """
        registry: dict[tuple, str] = self._state.union_struct_layouts
        minted_names = set(registry.values())
        for fld_name, fld_ty in list(union_struct.fields.items()):
            nested = self._pointee_struct(fld_ty)
            if nested is not None and nested._name not in minted_names:  # pylint:disable=protected-access
                union_struct.fields[fld_name] = SimTypePointer(SimTypeBottom(label="void")).with_arch(self.project.arch)

    def _canonicalize_union_struct(self, union_struct: SimStruct) -> TypeRef:
        """
        Return a project-wide canonical TypeRef for the given struct layout: reuse a previously-unioned struct with an
        identical layout if one exists, otherwise register the given struct under a fresh unique name. This keeps
        repeated unions of the same layout (across values, functions, and re-decompilations) from proliferating
        duplicate typedefs. Only structs minted by this canonicalization are candidates for reuse — reusing
        translator- or user-named structs by structural equality risks name collisions with per-function type names.
        """
        # session-lifetime registry of layouts we minted, kept on the types store (deliberately not serialized)
        registry: dict[tuple, str] = self._state.union_struct_layouts

        signature = self._struct_layout_signature(union_struct)
        if signature is not None and signature in registry:
            existing_name = registry[signature]
            if existing_name in self.kb.types:
                existing = self.kb.types.get_own(existing_name)
                if isinstance(existing.ty, SimStruct):
                    return existing

        # deterministic naming: kb.types.unique_type_name() falls back to random names once the fruit pool is
        # exhausted, which would make decompilation output non-deterministic on binaries with many unioned structs
        ctr = len(registry)
        while f"ustruct_{ctr}" in self.kb.types:
            ctr += 1
        name = f"ustruct_{ctr}"
        union_struct._name = name  # pylint:disable=protected-access
        ref = TypeRef(name, union_struct).with_arch(self.project.arch)
        self.kb.types[name] = ref
        if signature is not None:
            registry[signature] = name
        return ref

    def register_referenced_union_structs(self, var_manager, vr=None, solved_types=()) -> None:
        """
        Ensure canonical union structs referenced by this function's variable types or prototype are present in the
        per-function type store, which the code generator emits typedefs from. Union structs are registered in the
        project-wide ``kb.types`` when minted; without this, a function whose variables reference one (e.g. through a
        back-propagated callee prototype) would use the type name without ever declaring it.
        """
        registry: dict[tuple, str] = self._state.union_struct_layouts
        minted_names = set(registry.values())
        if not minted_names:
            return
        worklist: list = list(var_manager.variable_to_types.values())
        if vr is not None:
            global_manager = self._global_manager()
            worklist += [global_manager.get_variable_type(v) for v in vr.var_to_typevars if self._is_global_variable(v)]
        own_proto = self.function.get_prototype(self.flavor)
        if own_proto is not None:
            worklist += list(own_proto.args or ())
            worklist.append(own_proto.returnty)
        # expression types come straight from the Typehoon solution (e.g. the type of a value stored into a field), so
        # every solved type is a candidate as well
        worklist += list(solved_types)
        # casts at call sites carry the callees' argument types, which may name union structs too
        callgraph = self.kb.functions.callgraph
        if self.function.addr in callgraph:
            for callee_addr in callgraph.successors(self.function.addr):
                if self.kb.functions.contains_addr(callee_addr):
                    callee_proto = self.kb.functions.get_by_addr(callee_addr).get_prototype(self.flavor)
                    if callee_proto is not None:
                        worklist += list(callee_proto.args or ())
        # walk field types transitively: a union struct referenced only as the type of another struct's field still
        # shows up in the output (e.g. as a cast on a field store) and needs its typedef
        seen: set[int] = set()
        while worklist:
            ty = worklist.pop()
            if ty is None:
                continue
            struct = self._pointee_struct(ty)
            if struct is None:
                inner = ty.ty if isinstance(ty, TypeRef) else ty
                struct = inner if isinstance(inner, SimStruct) else None
            if struct is None or id(struct) in seen:
                continue
            seen.add(id(struct))
            name = struct._name  # pylint:disable=protected-access
            if name in minted_names and name not in var_manager.types and name in self.kb.types:
                var_manager.types[name] = self.kb.types.get_own(name)
            worklist.extend(struct.fields.values())

    @staticmethod
    def _layouts_consistent(structs: list[SimStruct]) -> bool:
        """
        Whether several layouts describe the same object: at every offset that more than one layout populates the
        fields must have the same size, and no field may start inside another layout's field.
        """
        spans: dict[int, int] = {}
        for struct in structs:
            offsets = struct.offsets
            for name, fld_ty in struct.fields.items():
                if name.startswith("padding_"):
                    continue
                offset = offsets.get(name)
                if offset is None:
                    continue
                try:
                    size = fld_ty.size // 8 if fld_ty.size else 1
                except Exception:  # pylint:disable=broad-except
                    size = 1
                if offset in spans:
                    if spans[offset] != size:
                        return False
                    continue
                for other_off, other_size in spans.items():
                    if other_off < offset < other_off + other_size or offset < other_off < offset + size:
                        return False
                spans[offset] = size
        return True

    def _union_of_evidence(self, candidates: list[SimType]) -> tuple[TypeRef, SimStruct] | None:
        """Union candidate layouts into a canonical union struct, or None when the evidence does not make a struct."""
        # layouts recorded from raw access offsets (weak) may complete a struct, but never make one on their own
        weak = self._state.weak_layouts
        if not any(id(c) not in weak and self._pointee_struct(c) is not None for c in candidates):
            return None
        union = union_pointer_struct_types(candidates, self.project.arch)
        union_struct = self._pointee_struct(union)
        if union_struct is None:
            return None
        # only synthesize a struct when there is genuine multi-field evidence; a single field at one offset is just
        # a scalar pointer (e.g. a char*), and turning it into a struct would clobber better scalar-pointer types.
        if self._real_field_count(union_struct) < 2:
            return None
        # drop nested references to per-function-named structs: carrying e.g. a callee-local "struct_1 *" field
        # into the caller collides with the caller's own per-function type names
        self._sanitize_union_struct_fields(union_struct)
        # reuse a project-wide canonical struct for this layout (or register a fresh one) so identical unions
        # across values, functions, and re-decompilations share a single typedef
        canonical_ref = self._canonicalize_union_struct(union_struct)
        # remember what the struct was built from; a later union that meets it expands it into these layouts
        provenance = self._state.union_struct_evidence.setdefault(canonical_ref.name, [])
        known = {id(x) for x in provenance}
        for layout in candidates:
            if id(layout) not in known and not self._is_minted_union_type(layout):
                provenance.append(layout)
                known.add(id(layout))
        return canonical_ref, union_struct

    @staticmethod
    def value_sources(ail_graph) -> dict[int, set[int]]:
        """
        For every SSA value defined by a phi or a plain copy of another value, the values it is made of. A value
        reaches an argument when the argument is among its sources, transitively (see :meth:`_reaching_values`).
        """
        sources: dict[int, set[int]] = defaultdict(set)
        if ail_graph is None:
            return sources
        for block in ail_graph:
            for stmt in block.statements:
                if not (isinstance(stmt, Assignment) and isinstance(stmt.dst, ailment.Expr.VirtualVariable)):
                    continue
                src = stmt.src
                if isinstance(src, ailment.Expr.Phi):
                    for _, vvar in src.src_and_vvars:
                        if vvar is not None:
                            sources[stmt.dst.varid].add(vvar.varid)
                elif isinstance(src, ailment.Expr.VirtualVariable):
                    sources[stmt.dst.varid].add(src.varid)
        return sources

    @staticmethod
    def _reaching_values(value_id: int, sources: dict[int, set[int]]) -> set[int]:
        """Every value ``value_id`` may be: itself and, transitively, the sources of the phis and copies it comes from."""
        seen = {value_id}
        stack = [value_id]
        while stack:
            for src in sources.get(stack.pop(), ()):
                if src not in seen:
                    seen.add(src)
                    stack.append(src)
        return seen

    def _argument_derived_observations(self, observations, arg_vvars, value_sources) -> dict[int, list]:
        """
        Call-site observations whose value may be one of this function's arguments without being the argument's own
        SSA value, keyed by id() of the argument's variable.
        """
        derived: dict[int, list] = defaultdict(list)
        if not value_sources or not arg_vvars:
            return derived
        arg_by_value = {vvar.varid: arg_var for vvar, arg_var in arg_vvars.values() if vvar is not None}
        for entries in observations.values():
            for entry in entries:
                value_id = entry[3]
                if not isinstance(value_id, int) or value_id in arg_by_value:
                    continue
                for src in self._reaching_values(value_id, value_sources):
                    arg_var = arg_by_value.get(src)
                    if arg_var is not None:
                        derived[id(arg_var)].append(entry)
        return derived

    def unify_callee_argument_structs(self, vr, var_manager, arg_vvars=None, value_sources=None) -> None:
        """
        Progressively unify partial struct layouts recovered for the same caller value across multiple callees.

        For each caller value that is passed as a pointer argument to one or more callees, union the layouts the
        callees' own accesses imply (plus the layout the caller's own accesses imply) into a single struct, pin it onto
        the caller value, and back-propagate the combined struct to the involved callees so subsequent decompilations
        stay consistent and become progressively more complete. Only direct evidence is unioned: a struct minted by an
        earlier union is never an input to the next one, so contamination cannot compound across functions.

        Observations are grouped by the SSA value that reached the call site. Each value gets its own union and its
        own back-propagation; the caller variable, which variable recovery may have shared between several values, is
        only pinned when those per-value unions agree with each other.
        """
        # even a function that passes no pointer to any callee may touch a global whose layout other functions have
        # already assembled, so there is no early exit on an empty observation set
        observations = getattr(vr, "arg_struct_observations", None) or {}
        arch = self.project.arch
        global_content = self._global_content_observations(observations)
        arg_index = {id(arg_var): arg_idx for arg_idx, (_, arg_var) in (arg_vvars or {}).items()}
        derived = self._argument_derived_observations(observations, arg_vvars, value_sources)
        for variable, tvs in vr.var_to_typevars.items():
            is_global = self._is_global_variable(variable)
            groups: dict = {}
            per_tv = [(tv, list(observations.get(tv, ()))) for tv in tvs]
            if id(variable) in derived:
                # values that may be this argument (a loop pointer that starts at it, a copy of it) are passed to
                # callees under another variable; what those callees learned is about this argument too
                per_tv.append((None, derived[id(variable)]))
            for tv, observed_here in per_tv:
                if is_global:
                    # the value passed to callees is the global's content; every call site loads the same object
                    observed_here += [(a, i, t, ("global", variable.addr)) for a, i, t, _ in global_content.get(tv, ())]
                for callee_addr, arg_idx, simtype, value_id in observed_here:
                    key = value_id if value_id is not None else ("tv", tv)
                    group = groups.setdefault(key, {"observed": [], "contributors": [], "contaminated": set()})
                    group["contributors"].append((callee_addr, arg_idx))
                    if self._is_minted_union_type(simtype):
                        # fields a previous union pushed into this callee are not evidence, and Typehoon has copied
                        # them into the caller's local as well; remember them so the caller's own type can be cleaned
                        pushed = self._pointee_struct(simtype)
                        group["contaminated"].update(
                            off for name, off in pushed.offsets.items() if not name.startswith("padding_")
                        )
                    group["observed"].extend(self._contributor_evidence(callee_addr, arg_idx, simtype))
            type_manager = self._global_manager() if is_global else var_manager
            current = type_manager.get_variable_type(variable)
            # a global struct accessed by value: every function sees the members it touches; union the views the
            # same way as for a pointer, with the object itself as the layout
            by_value = False
            if (
                is_global
                and current is not None
                and self._struct_of(current) is None
                and self._pointee_struct(current) is None
            ):
                # a scalar or array view (Typehoon may also solve it as a pointer to an array) of an object this
                # function touched at constant offsets (g.x and g.y read like g[0] and g[1]): its members are the
                # offsets it accessed (weak evidence). A pointer global only ever loads its value at offset 0 and
                # gets no such layout.
                accessed = self._accessed_member_layout(vr, variable)
                if accessed is not None:
                    by_value = True
                    current = accessed
            if (
                is_global
                and not by_value
                and not isinstance(current, SimTypePointer)
                and self._global_object_view(variable, current)
            ):
                by_value = True
                current = SimTypePointer(self._struct_of(current) or current).with_arch(arch)
            if is_global and (("global", variable.addr) in self._state.own_local_layouts or by_value):
                # a global that took part in a union before: this function's view joins the recorded ones even when
                # it passes the global to no callee, and the result goes back to every callee that ever received it
                group = groups.setdefault(
                    ("global", variable.addr), {"observed": [], "contributors": [], "contaminated": set()}
                )
                group["contributors"] += sorted(self._state.global_union_contributors.get(variable.addr, ()))
            if id(variable) in arg_index:
                # the callee arguments this argument is passed on to, for _has_struct_evidence
                self._state.arg_forward_targets[(self.function.addr, arg_index[id(variable)])] = {
                    contributor for group in groups.values() for contributor in group["contributors"]
                }
            if not groups:
                continue
            if id(variable) in arg_index:
                # what this function and its callees learned about the argument, for the callers above it: its own
                # layout and every callee's contribution, never what a caller pushed in
                arg_idx = arg_index[id(variable)]
                own = self._state.own_arg_layouts.get((self.function.addr, arg_idx))
                down = [own] if own is not None else []
                known = {id(x) for x in down}
                for group in groups.values():
                    for layout in group["observed"]:
                        if id(layout) not in known:
                            down.append(layout)
                            known.add(id(layout))
                self._state.arg_downward_evidence[(self.function.addr, arg_idx)] = down
            unions: list[tuple[TypeRef, SimStruct, list[tuple[int, int]]]] = []
            for key, group in groups.items():
                candidates = list(group["observed"])
                # include the layout the caller's own accesses imply so caller-side fields are preserved in the union
                caller_evidence = self._caller_evidence(variable, current, arg_vvars, group["contaminated"])
                if isinstance(key, int) or is_global:
                    # keep the layouts seen for this value on earlier decompilations: once the local is typed by the
                    # unions its callees carry, the caller's own fields can no longer be told apart from them. For a
                    # global the record also keeps the callee-side views, since every function that touches the
                    # global recomputes its union from this record alone.
                    record_key = ("global", variable.addr) if is_global else (self.function.addr, key)
                    recorded = self._state.own_local_layouts.setdefault(record_key, [])
                    known = {id(x) for x in recorded}
                    for layout in (caller_evidence + candidates) if is_global else caller_evidence:
                        if id(layout) not in known:
                            recorded.append(layout)
                            known.add(id(layout))
                    caller_evidence = list(recorded) if not is_global else []
                    if is_global:
                        candidates = list(recorded)
                candidates.extend(caller_evidence)
                if not candidates:
                    continue
                result = self._union_of_evidence(candidates)
                if result is None:
                    continue
                canonical_ref, union_struct = result
                unions.append((canonical_ref, union_struct, group["contributors"]))
            if not unions:
                continue

            # each value's union goes back to the callees that saw that value
            for canonical_ref, _, contributors in unions:
                if is_global:
                    self._state.global_union_contributors.setdefault(variable.addr, set()).update(contributors)
                self._propagate_arg_struct_to_callees(contributors, SimTypePointer(canonical_ref).with_arch(arch))

            # pin the caller variable only when every value it carried agrees on the layout
            if len(unions) == 1:
                canonical_ref, union_struct, _ = unions[0]
            else:
                if not self._layouts_consistent([us for _, us, _ in unions]):
                    continue
                result = self._union_of_evidence([SimTypePointer(us).with_arch(arch) for _, us, _ in unions])
                if result is None:
                    continue
                canonical_ref, union_struct = result
            union_ptr = SimTypePointer(canonical_ref).with_arch(arch)

            # skip when what we have is already at least as detailed: strictly more fields, or a layout that already
            # holds every member of the union. A union that adds nothing must not rename the value's own struct (it
            # would also lose nested struct pointers to the field sanitizer); it has already been recorded and pushed.
            current_struct = self._pointee_struct(current)
            if current_struct is not None and (
                self._real_field_count(current_struct) > self._real_field_count(union_struct)
                or self._layout_covers(current_struct, union_struct)
            ):
                continue

            type_manager.set_variable_type(variable, canonical_ref if by_value else union_ptr, all_unified=True)

    @staticmethod
    def _layout_covers(big: SimStruct, small: SimStruct) -> bool:
        """Whether every non-padding field of ``small`` exists in ``big`` at the same offset with at least its size."""

        def sizes(struct: SimStruct) -> dict[int, int]:
            offsets = struct.offsets
            out: dict[int, int] = {}
            for name, fld_ty in struct.fields.items():
                if name.startswith("padding_") or offsets.get(name) is None:
                    continue
                try:
                    out[offsets[name]] = fld_ty.size // 8 if fld_ty.size else 1
                except Exception:  # pylint:disable=broad-except
                    out[offsets[name]] = 1
            return out

        big_sizes = sizes(big)
        return all(offset in big_sizes and big_sizes[offset] >= size for offset, size in sizes(small).items())

    def _propagate_arg_struct_to_callees(self, contributors: list[tuple[int, int]], union_ptr: SimTypePointer) -> None:
        """
        Upgrade callee prototype argument types to the unioned struct. A callee's argument is only rewritten when the
        union covers the layout the callee's own accesses imply: a union that lost one of the callee's fields (an
        overlapping caller-side field, a different value) would otherwise be pinned onto the callee as ground truth
        and take that field away from it.
        """
        union_struct = self._pointee_struct(union_ptr)
        if union_struct is None:
            return
        for callee_addr, arg_idx in set(contributors):
            if not self.kb.functions.contains_addr(callee_addr):
                continue
            callee = self.kb.functions.get_by_addr(callee_addr)
            proto = callee.get_prototype(self.flavor)
            if proto is None or arg_idx >= len(proto.args):
                continue
            # never rewrite library, PLT, SimProcedure, signature-matched, or user-specified prototypes: a rewritten
            # library prototype (e.g. strcmp) becomes ground truth for every later caller and spreads the struct to
            # every string passed to it
            if not callee.is_prototype_refinable_for(self.flavor):
                continue
            # a callee that never dereferences the argument may be receiving any object; the union is only the caller's
            if not self._has_struct_evidence(callee_addr, arg_idx):
                continue
            # never take a field away from the callee: the union must cover what its own accesses established
            if not self._covers_own_layout(union_struct, callee_addr, arg_idx):
                continue
            # nor hide an access: whatever type the callee's argument was solved as, every offset its own code touches
            # must land inside a member of the union, or the callee would render it as a dereference of padding
            accessed = self._state.arg_accessed_fields.get((callee_addr, arg_idx))
            if accessed and not self._union_covers_accesses(union_struct, accessed):
                continue
            # skip when the callee already has strictly more detail, or the exact same canonical struct; an
            # equal-count layout under a different name is still rewritten so all contributors share one typedef
            existing_struct = self._pointee_struct(proto.args[arg_idx])
            if existing_struct is not None and (
                self._real_field_count(existing_struct) > self._real_field_count(union_struct)
                or (
                    self._real_field_count(existing_struct) == self._real_field_count(union_struct)
                    and existing_struct._name == union_struct._name  # pylint:disable=protected-access
                )
            ):
                continue
            self._state.pushed_arg_unions[(callee_addr, arg_idx)] = union_ptr
            new_args = list(proto.args)
            new_args[arg_idx] = union_ptr
            callee.set_prototype(
                self.flavor,
                SimTypeFunction(new_args, proto.returnty, arg_names=proto.arg_names, variadic=proto.variadic).with_arch(
                    self.project.arch
                ),
            )

    def populate_global_variables(self, global_manager: VariableManagerInternal) -> None:
        """
        Populate a global variable manager with the boundaries of known global data objects, so that variable recovery
        groups accesses landing inside the same object.
        """
        for symbol in self.project.loader.main_object.symbols:
            if symbol.type != SymbolType.TYPE_OBJECT or not symbol.size:
                continue
            addr = symbol.rebased_addr
            if global_manager.get_global_variables(addr):
                continue
            variable = SimMemoryVariable(
                addr, symbol.size, name=symbol.name, ident=global_manager.next_variable_ident("global")
            )
            variable.renamed = True
            global_manager.set_variable("global", addr, variable)
