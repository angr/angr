from __future__ import annotations

import logging
from collections.abc import Callable
from typing import TYPE_CHECKING, Any

import archinfo

import angr
from angr.rust.sim_type import EnumVariant
from angr.sim_type import SimType

if TYPE_CHECKING:
    from angr.ailment.manager import Manager
    from angr.ailment.tagged_object import TaggedObject
    from angr.rustylib.ailment import Expression, Statement

    # Anything carrying an ``.idx`` that the map can key on: the rustlib
    # Expression / Statement pyclasses plus pure-Python TaggedObject
    # subclasses (structurer helper nodes).
    AILObject = TaggedObject | Expression | Statement
    from angr.calling_conventions import SimCC
    from angr.sim_type import SimTypeFunction
    from angr.sim_variable import SimVariable


_l = logging.getLogger(name=__name__)


def variable_map_of(manager: Manager) -> VariableMap:
    """
    Return the :class:`VariableMap` attached to an ailment ``Manager``, lazily creating and attaching an empty one if
    the manager does not have a map yet (e.g. Managers constructed outside of Clinic in tests). This keeps consumers
    that reach the map through ``manager.variable_map`` from having to special-case ``None``.
    """

    vm = manager.variable_map
    if vm is None:
        vm = VariableMap()
        manager.variable_map = vm
    return vm


class VariableMap:
    """
    A side container that maps AIL :class:`Statement` and :class:`Expression` objects to variable-related information.

    The following pieces of information are tracked:

    - ``variable`` (a :class:`SimVariable`) and ``variable_offset`` (an ``int``): the variable that an AIL atom
      resolves to, and the offset into that variable.
    - ``custom_string`` (a ``bool``): whether a ``Const`` expression refers to a custom string.
    - ``reference_values`` (a ``dict`` mapping :class:`SimType` to a value): reference values associated with a
      ``Const`` expression (e.g., custom strings).
    - ``reference_variable`` (a :class:`SimVariable`) and ``reference_variable_offset`` (an ``int``): the variable
      that a constant expression references, and the offset into it. These are siblings of ``variable`` /
      ``variable_offset`` that are specifically used for constants that reference global/extern variables.
    - ``prototype`` (a :class:`SimTypeFunction`) and ``calling_convention`` (a :class:`SimCC`): the call-site
      prototype and calling convention associated with an AIL :class:`Call` expression. These used to live directly
      on the ``Call`` object; they are heavy, non-serializable Python references, so they are tracked here instead.
    - ``variant`` (an ``EnumVariant``): the enum variant that a Rust ``Let`` expression binds.
    - ``returnty`` (a :class:`SimType`): the return type of a Rust ``FunctionLikeMacro`` call.

    Most information is keyed by the integer ``.idx`` of an AIL atom. Variable and variable-offset information uses a
    separate namespace for ``VirtualVariable`` atoms: a stable ``.varid`` default plus occurrence-specific overrides
    and tombstones keyed by ``(.varid, .idx)``. Transformation passes can create different atom kinds with the same
    ``.idx``, while duplicate ``VirtualVariable`` wrappers may have different ``.idx`` values for the same ``.varid``.
    A VariableMap is scoped to one Clinic instance and is stored in the corresponding :class:`DecompilationCache`.
    """

    __slots__ = (
        "_calling_conventions",
        "_custom_strings",
        "_prototypes",
        "_reference_values",
        "_reference_variable_offsets",
        "_reference_variables",
        "_returntys",
        "_variable_offsets",
        "_variables",
        "_variants",
        "_vvar_id_to_variable",
        "_vvar_id_to_variable_offset",
        "_vvar_occurrence_tombstones",
        "_vvar_occurrence_variable_offsets",
        "_vvar_occurrence_variables",
    )

    SERIALIZATION_VERSION = 2

    def __init__(self):
        self._variables: dict[int, SimVariable] = {}
        self._variable_offsets: dict[int, int] = {}
        self._custom_strings: dict[int, bool] = {}
        self._reference_values: dict[int, dict[SimType, Any]] = {}
        self._reference_variables: dict[int, SimVariable] = {}
        self._reference_variable_offsets: dict[int, int] = {}
        self._prototypes: dict[int, SimTypeFunction] = {}
        self._calling_conventions: dict[int, SimCC] = {}
        # ``variant`` (an ``EnumVariant``): the enum variant a Rust ``Let`` expression binds.
        self._variants: dict[int, Any] = {}
        # ``returnty`` (a :class:`SimType`): the return type of a Rust ``FunctionLikeMacro`` call.
        self._returntys: dict[int, SimType] = {}
        # VirtualVariable atoms use a stable varid default plus occurrence-specific overrides. A tombstone suppresses
        # the stable default for one explicitly cleared wrapper without affecting other wrappers for the same varid.
        self._vvar_id_to_variable: dict[int, SimVariable] = {}
        self._vvar_id_to_variable_offset: dict[int, int] = {}
        self._vvar_occurrence_variables: dict[tuple[int, int], SimVariable] = {}
        self._vvar_occurrence_variable_offsets: dict[tuple[int, int], int] = {}
        self._vvar_occurrence_tombstones: set[tuple[int, int]] = set()

    #
    # Key helper
    #

    @staticmethod
    def _key(obj: AILObject | int) -> int:
        return obj if isinstance(obj, int) else obj.idx

    @staticmethod
    def _varid(obj: AILObject | int) -> int | None:
        return None if isinstance(obj, int) else getattr(obj, "varid", None)

    @classmethod
    def _vvar_key(cls, obj: AILObject | int) -> tuple[int, int] | None:
        varid = cls._varid(obj)
        return None if varid is None else (varid, cls._key(obj))

    #
    # Accessors
    #

    def variable(self, obj: AILObject | int) -> SimVariable | None:
        vvar_key = self._vvar_key(obj)
        if vvar_key is not None:
            if vvar_key in self._vvar_occurrence_tombstones:
                return None
            if vvar_key in self._vvar_occurrence_variables:
                return self._vvar_occurrence_variables[vvar_key]
            return self._vvar_id_to_variable.get(vvar_key[0])
        return self._variables.get(self._key(obj))

    def variable_offset(self, obj: AILObject | int) -> int:
        vvar_key = self._vvar_key(obj)
        if vvar_key is not None:
            if vvar_key in self._vvar_occurrence_tombstones:
                return 0
            if vvar_key in self._vvar_occurrence_variable_offsets:
                return self._vvar_occurrence_variable_offsets[vvar_key]
            return self._vvar_id_to_variable_offset.get(vvar_key[0], 0)
        return self._variable_offsets.get(self._key(obj), 0)

    def custom_string(self, obj: AILObject | int) -> bool:
        return self._custom_strings.get(self._key(obj), False)

    def reference_values(self, obj: AILObject | int) -> dict[SimType, Any] | None:
        return self._reference_values.get(self._key(obj))

    def reference_variable(self, obj: AILObject | int) -> SimVariable | None:
        return self._reference_variables.get(self._key(obj))

    def reference_variable_offset(self, obj: AILObject | int) -> int:
        return self._reference_variable_offsets.get(self._key(obj), 0)

    def has_variable(self, obj: AILObject | int) -> bool:
        vvar_key = self._vvar_key(obj)
        if vvar_key is not None:
            if vvar_key in self._vvar_occurrence_tombstones:
                return False
            return vvar_key in self._vvar_occurrence_variables or vvar_key[0] in self._vvar_id_to_variable
        return self._key(obj) in self._variables

    def prototype(self, obj: AILObject | int) -> SimTypeFunction | None:
        return self._prototypes.get(self._key(obj))

    def calling_convention(self, obj: AILObject | int) -> SimCC | None:
        return self._calling_conventions.get(self._key(obj))

    def variant(self, obj: AILObject | int) -> Any:
        return self._variants.get(self._key(obj))

    def returnty(self, obj: AILObject | int) -> SimType | None:
        return self._returntys.get(self._key(obj))

    #
    # Setters
    #

    def set_variable(self, obj: AILObject | int, variable: SimVariable | None, offset: int = 0) -> None:
        """Set the variable information for an AIL atom. If ``variable`` is ``None``, the variable information for
        this atom is cleared."""

        vvar_key = self._vvar_key(obj)
        if vvar_key is not None:
            if variable is None:
                self._vvar_occurrence_variables.pop(vvar_key, None)
                self._vvar_occurrence_variable_offsets.pop(vvar_key, None)
                self._vvar_occurrence_tombstones.add(vvar_key)
            else:
                self._vvar_occurrence_variables[vvar_key] = variable
                self._vvar_occurrence_variable_offsets[vvar_key] = offset
                self._vvar_occurrence_tombstones.discard(vvar_key)
                self._vvar_id_to_variable[vvar_key[0]] = variable
                self._vvar_id_to_variable_offset[vvar_key[0]] = offset
            return

        key = self._key(obj)
        if variable is None:
            self._variables.pop(key, None)
            self._variable_offsets.pop(key, None)
        else:
            self._variables[key] = variable
            self._variable_offsets[key] = offset

    def set_variable_offset(self, obj: AILObject | int, offset: int) -> None:
        vvar_key = self._vvar_key(obj)
        if vvar_key is not None:
            self._vvar_occurrence_variable_offsets[vvar_key] = offset
        else:
            self._variable_offsets[self._key(obj)] = offset

    def set_custom_string(self, obj: AILObject | int, value: bool = True) -> None:
        self._custom_strings[self._key(obj)] = value

    def set_reference_values(self, obj: AILObject | int, reference_values: dict[SimType, Any]) -> None:
        self._reference_values[self._key(obj)] = reference_values

    def set_reference_variable(self, obj: AILObject | int, variable: SimVariable | None, offset: int = 0) -> None:
        """Set the reference variable information for an AIL atom. If ``variable`` is ``None``, the reference variable information for
        this atom is cleared."""
        key = self._key(obj)
        if variable is None:
            self._reference_variables.pop(key, None)
            self._reference_variable_offsets.pop(key, None)
        else:
            self._reference_variables[key] = variable
            self._reference_variable_offsets[key] = offset

    def set_prototype(self, obj: AILObject | int, prototype: SimTypeFunction | None) -> None:
        """Set the call-site prototype for an AIL Call. If ``prototype`` is ``None``, the prototype information for
        this atom is cleared."""

        key = self._key(obj)
        if prototype is None:
            self._prototypes.pop(key, None)
        else:
            self._prototypes[key] = prototype

    def set_calling_convention(self, obj: AILObject | int, cc: SimCC | None) -> None:
        """Set the calling convention for an AIL Call. If ``cc`` is ``None``, the calling-convention information for
        this atom is cleared."""

        key = self._key(obj)
        if cc is None:
            self._calling_conventions.pop(key, None)
        else:
            self._calling_conventions[key] = cc

    def set_variant(self, obj: AILObject | int, variant: Any) -> None:
        """Set the enum variant for a Rust ``Let`` expression. If ``variant`` is ``None``, the variant information for
        this atom is cleared."""

        key = self._key(obj)
        if variant is None:
            self._variants.pop(key, None)
        else:
            self._variants[key] = variant

    def set_returnty(self, obj: AILObject | int, returnty: SimType | None) -> None:
        """Set the return type for a Rust ``FunctionLikeMacro`` call. If ``returnty`` is ``None``, the return-type
        information for this atom is cleared."""

        key = self._key(obj)
        if returnty is None:
            self._returntys.pop(key, None)
        else:
            self._returntys[key] = returnty

    def transfer(self, src: AILObject | int, dst: AILObject | int, vvar_id: int | None = None) -> None:
        """
        Copy all variable information associated with ``src`` to ``dst``. Used when an AIL atom is deep-copied to a new
        ``.idx`` (e.g. during structuring/duplication) so that the new atom keeps the same variable association.

        Native AIL deep-copy passes integer indices. For a ``VirtualVariable`` it also supplies ``vvar_id`` so this
        method uses the VVar occurrence namespace and cannot copy state owned by a colliding non-VVar atom.
        """

        src_key = self._key(src)
        dst_key = self._key(dst)
        src_varid = vvar_id if vvar_id is not None else self._varid(src)
        dst_varid = vvar_id if vvar_id is not None else self._varid(dst)

        if src_varid is not None or dst_varid is not None:
            src_vvar_key = (src_varid, src_key) if src_varid is not None else None
            dst_vvar_key = (dst_varid, dst_key) if dst_varid is not None else None
            if src_vvar_key is not None and src_vvar_key in self._vvar_occurrence_tombstones:
                if dst_vvar_key is not None:
                    self._vvar_occurrence_variables.pop(dst_vvar_key, None)
                    self._vvar_occurrence_variable_offsets.pop(dst_vvar_key, None)
                    self._vvar_occurrence_tombstones.add(dst_vvar_key)
                else:
                    self.set_variable(dst, None)
                return

            variable = None
            has_variable = False
            offset = 0
            has_offset = False
            if src_vvar_key is not None:
                if src_vvar_key in self._vvar_occurrence_variables:
                    variable = self._vvar_occurrence_variables[src_vvar_key]
                    has_variable = True
                elif src_varid in self._vvar_id_to_variable:
                    variable = self._vvar_id_to_variable[src_varid]
                    has_variable = True
                if src_vvar_key in self._vvar_occurrence_variable_offsets:
                    offset = self._vvar_occurrence_variable_offsets[src_vvar_key]
                    has_offset = True
                elif src_varid in self._vvar_id_to_variable_offset:
                    offset = self._vvar_id_to_variable_offset[src_varid]
                    has_offset = True
            else:
                if src_key in self._variables:
                    variable = self._variables[src_key]
                    has_variable = True
                if src_key in self._variable_offsets:
                    offset = self._variable_offsets[src_key]
                    has_offset = True

            if dst_vvar_key is not None:
                if has_variable:
                    self._vvar_occurrence_variables[dst_vvar_key] = variable  # type: ignore[assignment]
                if has_offset:
                    self._vvar_occurrence_variable_offsets[dst_vvar_key] = offset
                if has_variable or has_offset:
                    self._vvar_occurrence_tombstones.discard(dst_vvar_key)
            else:
                if has_variable:
                    self.set_variable(dst, variable, offset)  # type: ignore[arg-type]
                elif has_offset:
                    self.set_variable_offset(dst, offset)
            return

        if src_key == dst_key:
            return
        for d in (
            self._variables,
            self._variable_offsets,
            self._custom_strings,
            self._reference_values,
            self._reference_variables,
            self._reference_variable_offsets,
            self._prototypes,
            self._calling_conventions,
            self._variants,
            self._returntys,
        ):
            if src_key in d:
                d[dst_key] = d[src_key]  # type:ignore

    #
    # Serialization
    #

    @staticmethod
    def _reference_values_to_json(d: dict[SimType, Any]) -> list[dict[str, Any]]:
        items = []
        for ty, value in d.items():
            ty_json = ty.to_json() if isinstance(ty, SimType) else None
            items.append({"type": ty_json, "value": value if isinstance(value, (str, int, float, bool)) else None})
        return items

    @staticmethod
    def _reference_values_from_json(items: list[dict[str, Any]]) -> dict[SimType, Any]:
        d: dict[SimType, Any] = {}
        for item in items:
            ty_json = item.get("type")
            if ty_json is None:
                continue
            ty = SimType.from_json(ty_json)
            d[ty] = item.get("value")
        return d

    @staticmethod
    def _cc_to_json(cc: SimCC) -> dict[str, Any]:
        # Calling conventions are serialized by class name + arch name and reconstructed from the arch on load.
        # TODO: Preserve custom argument/return locations of SimCCUsercall.
        return {"cls": type(cc).__name__, "arch": cc.arch.name if cc.arch is not None else None}

    @staticmethod
    def _cc_from_json(d: dict[str, Any]) -> SimCC | None:
        CC_NAMES = angr.calling_conventions.CC_NAMES
        cls_name = d.get("cls")
        cls = CC_NAMES.get(cls_name) if cls_name else None
        if cls is None or not isinstance(cls, type) or not issubclass(cls, angr.calling_conventions.SimCC):
            _l.warning("Calling convention class %s could not be resolved during VariableMap deserialization", cls_name)
            return None
        arch_name = d.get("arch")
        try:
            arch = archinfo.arch_from_id(arch_name) if arch_name else None
            if arch is None:
                return None
            return cls(arch)
        except (TypeError, ValueError, KeyError):
            # SimCCUsercall and friends require extra (unserialized) arguments; reconstruction is not possible.
            _l.warning("Calling convention %s could not be reconstructed during VariableMap deserialization", cls_name)
            return None

    def to_json(self) -> dict[str, Any]:
        """
        Serialize this VariableMap to a JSON-compatible object.

        Variables are referenced by their ``.ident`` (reference-by-ident); they must be resolved back to
        :class:`SimVariable` objects via a resolver in :meth:`from_json`.
        """

        return {
            "version": self.SERIALIZATION_VERSION,
            "variables": {idx: (v.ident if v is not None else None) for idx, v in self._variables.items()},
            "variable_offsets": dict(self._variable_offsets),
            "vvar_id_to_variable": {
                varid: (v.ident if v is not None else None) for varid, v in self._vvar_id_to_variable.items()
            },
            "vvar_id_to_variable_offset": dict(self._vvar_id_to_variable_offset),
            "vvar_occurrence_variables": [
                {"varid": varid, "idx": idx, "variable": variable.ident}
                for (varid, idx), variable in sorted(self._vvar_occurrence_variables.items())
            ],
            "vvar_occurrence_variable_offsets": [
                {"varid": varid, "idx": idx, "offset": offset}
                for (varid, idx), offset in sorted(self._vvar_occurrence_variable_offsets.items())
            ],
            "vvar_occurrence_tombstones": [
                {"varid": varid, "idx": idx} for varid, idx in sorted(self._vvar_occurrence_tombstones)
            ],
            "custom_strings": dict(self._custom_strings),
            "reference_values": {idx: self._reference_values_to_json(d) for idx, d in self._reference_values.items()},
            "reference_variables": {
                idx: (v.ident if v is not None else None) for idx, v in self._reference_variables.items()
            },
            "reference_variable_offsets": dict(self._reference_variable_offsets),
            "prototypes": {idx: proto.to_json() for idx, proto in self._prototypes.items()},
            "calling_conventions": {idx: self._cc_to_json(cc) for idx, cc in self._calling_conventions.items()},
            "variants": {
                idx: variant.to_json() for idx, variant in self._variants.items() if hasattr(variant, "to_json")
            },
            "returntys": {idx: ty.to_json() for idx, ty in self._returntys.items() if isinstance(ty, SimType)},
        }

    @classmethod
    def from_json(cls, data: dict[str, Any], resolve_variable: Callable[[str], SimVariable | None]) -> VariableMap:
        """
        Deserialize a VariableMap from a JSON-compatible object produced by :meth:`to_json`.

        :param data:             The JSON object.
        :param resolve_variable: A callable that maps a variable ident (``str``) to a :class:`SimVariable` (or
                                 ``None`` if it cannot be resolved).
        """

        version = data.get("version", 1)
        if version not in (1, cls.SERIALIZATION_VERSION):
            raise ValueError(f"Unsupported VariableMap serialization version {version}")
        if version == 1:
            _l.warning(
                "Deserializing legacy VariableMap serialization version 1; atom kinds were not recorded, so "
                "discarding all variable and offset bindings"
            )

        vm = cls()

        def _resolve(ident) -> SimVariable | None:
            return resolve_variable(ident) if ident is not None else None

        if version == cls.SERIALIZATION_VERSION:
            for idx, ident in data.get("variables", {}).items():
                v = _resolve(ident)
                if v is not None:
                    vm._variables[int(idx)] = v
                else:
                    _l.warning("Variable with ident %s could not be resolved during VariableMap deserialization", ident)
            for idx, offset in data.get("variable_offsets", {}).items():
                vm._variable_offsets[int(idx)] = offset

            resolved_vvar_ids: set[int] = set()
            for varid, ident in data.get("vvar_id_to_variable", {}).items():
                varid = int(varid)
                v = _resolve(ident)
                if v is not None:
                    vm._vvar_id_to_variable[varid] = v
                    resolved_vvar_ids.add(varid)
                else:
                    _l.warning("Variable with ident %s could not be resolved during VariableMap deserialization", ident)
            for varid, offset in data.get("vvar_id_to_variable_offset", {}).items():
                varid = int(varid)
                if varid in resolved_vvar_ids:
                    vm._vvar_id_to_variable_offset[varid] = offset

            resolved_occurrence_keys: set[tuple[int, int]] = set()
            unresolved_occurrence_keys: set[tuple[int, int]] = set()
            for entry in data.get("vvar_occurrence_variables", []):
                vvar_key = (int(entry["varid"]), int(entry["idx"]))
                v = _resolve(entry.get("variable"))
                if v is not None:
                    vm._vvar_occurrence_variables[vvar_key] = v
                    resolved_occurrence_keys.add(vvar_key)
                else:
                    _l.warning(
                        "Variable with ident %s could not be resolved during VariableMap deserialization",
                        entry.get("variable"),
                    )
                    unresolved_occurrence_keys.add(vvar_key)
            occurrence_offsets = {
                (int(entry["varid"]), int(entry["idx"])): entry["offset"]
                for entry in data.get("vvar_occurrence_variable_offsets", [])
            }
            resolved_occurrence_offset_keys = resolved_occurrence_keys | {
                vvar_key
                for vvar_key in occurrence_offsets
                if vvar_key[0] in resolved_vvar_ids and vvar_key not in unresolved_occurrence_keys
            }
            for vvar_key in resolved_occurrence_offset_keys:
                vm._vvar_occurrence_variable_offsets[vvar_key] = occurrence_offsets.get(vvar_key, 0)
            for vvar_key in unresolved_occurrence_keys:
                vm._vvar_occurrence_variables.pop(vvar_key, None)
                vm._vvar_occurrence_variable_offsets.pop(vvar_key, None)
                vm._vvar_occurrence_tombstones.add(vvar_key)
            for entry in data.get("vvar_occurrence_tombstones", []):
                vvar_key = (int(entry["varid"]), int(entry["idx"]))
                vm._vvar_occurrence_variables.pop(vvar_key, None)
                vm._vvar_occurrence_variable_offsets.pop(vvar_key, None)
                vm._vvar_occurrence_tombstones.add(vvar_key)
        for idx, value in data.get("custom_strings", {}).items():
            vm._custom_strings[int(idx)] = value
        for idx, items in data.get("reference_values", {}).items():
            vm._reference_values[int(idx)] = cls._reference_values_from_json(items)
        for idx, ident in data.get("reference_variables", {}).items():
            v = _resolve(ident)
            if v is not None:
                vm._reference_variables[int(idx)] = v
            else:
                _l.warning(
                    "Reference variable with ident %s could not be resolved during VariableMap deserialization", ident
                )
        for idx, offset in data.get("reference_variable_offsets", {}).items():
            vm._reference_variable_offsets[int(idx)] = offset
        for idx, proto_json in data.get("prototypes", {}).items():
            proto = SimType.from_json(proto_json)
            if proto is not None:
                vm._prototypes[int(idx)] = proto  # type: ignore[assignment]
        for idx, cc_json in data.get("calling_conventions", {}).items():
            cc = cls._cc_from_json(cc_json)
            if cc is not None:
                vm._calling_conventions[int(idx)] = cc
        for idx, variant_json in data.get("variants", {}).items():
            variant = EnumVariant.from_json(variant_json)
            if variant is not None:
                vm._variants[int(idx)] = variant
        for idx, ty_json in data.get("returntys", {}).items():
            ty = SimType.from_json(ty_json)
            if ty is not None:
                vm._returntys[int(idx)] = ty

        return vm
