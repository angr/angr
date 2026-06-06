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
    A side container that maps the ``.idx`` of AIL :class:`Statement` and :class:`Expression` objects to
    variable-related information.

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

    Keys are the integer ``.idx`` values of AIL Statement/Expression objects. Because :class:`Clinic` builds one
    :class:`ailment.Manager` per invocation, ``.idx`` values are unique within a single Clinic. So a VariableMap is
    scoped to one Clinic instance and is stored in the corresponding :class:`DecompilationCache`.
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
    )

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
        # Secondary index for VirtualVariable atoms keyed by their stable
        # ``varid``. Phase D minted fresh Expression wrappers (each carrying a
        # new ``.idx``) from intermediate passes that didn't propagate
        # variable_map entries via ``transfer``; without this fallback those
        # later vvar wrappers render as raw ``vvar_X`` in the C output even
        # though their varid was registered at variable-recovery time.
        self._vvar_id_to_variable: dict[int, SimVariable] = {}
        self._vvar_id_to_variable_offset: dict[int, int] = {}

    #
    # Key helper
    #

    @staticmethod
    def _key(obj: TaggedObject | int) -> int:
        return obj if isinstance(obj, int) else obj.idx

    #
    # Accessors
    #

    def variable(self, obj: TaggedObject | int) -> SimVariable | None:
        v = self._variables.get(self._key(obj))
        if v is not None:
            return v
        # VirtualVariable varid fallback: under Phase D, mid-pipeline
        # rewrites can re-wrap a vvar with a fresh ``.idx`` whose entry
        # was never registered. The varid is the stable SSA identifier,
        # so a same-varid hit is semantically equivalent.
        varid = getattr(obj, "varid", None)
        if varid is not None:
            return self._vvar_id_to_variable.get(varid)
        return None

    def variable_offset(self, obj: TaggedObject | int) -> int:
        key = self._key(obj)
        if key in self._variable_offsets:
            return self._variable_offsets[key]
        varid = getattr(obj, "varid", None)
        if varid is not None and varid in self._vvar_id_to_variable_offset:
            return self._vvar_id_to_variable_offset[varid]
        return 0

    def custom_string(self, obj: TaggedObject | int) -> bool:
        return self._custom_strings.get(self._key(obj), False)

    def reference_values(self, obj: TaggedObject | int) -> dict[SimType, Any] | None:
        return self._reference_values.get(self._key(obj))

    def reference_variable(self, obj: TaggedObject | int) -> SimVariable | None:
        return self._reference_variables.get(self._key(obj))

    def reference_variable_offset(self, obj: TaggedObject | int) -> int:
        return self._reference_variable_offsets.get(self._key(obj), 0)

    def has_variable(self, obj: TaggedObject | int) -> bool:
        if self._key(obj) in self._variables:
            return True
        varid = getattr(obj, "varid", None)
        return varid is not None and varid in self._vvar_id_to_variable

    def prototype(self, obj: TaggedObject | int) -> SimTypeFunction | None:
        return self._prototypes.get(self._key(obj))

    def calling_convention(self, obj: TaggedObject | int) -> SimCC | None:
        return self._calling_conventions.get(self._key(obj))

    def variant(self, obj: TaggedObject | int) -> Any:
        return self._variants.get(self._key(obj))

    def returnty(self, obj: TaggedObject | int) -> SimType | None:
        return self._returntys.get(self._key(obj))

    #
    # Setters
    #

    def set_variable(self, obj: TaggedObject | int, variable: SimVariable | None, offset: int = 0) -> None:
        """Set the variable information for an AIL atom. If ``variable`` is ``None``, the variable information for
        this atom is cleared."""

        key = self._key(obj)
        if variable is None:
            self._variables.pop(key, None)
            self._variable_offsets.pop(key, None)
        else:
            self._variables[key] = variable
            self._variable_offsets[key] = offset
        # Mirror into the varid-keyed secondary index so subsequent
        # lookups via a fresh-wrapper vvar of the same logical SSA
        # variable still resolve. We only mirror when ``obj`` carries a
        # ``varid`` -- i.e. it's a VirtualVariable instance (or wrapper).
        varid = getattr(obj, "varid", None)
        if varid is not None:
            if variable is None:
                self._vvar_id_to_variable.pop(varid, None)
                self._vvar_id_to_variable_offset.pop(varid, None)
            else:
                self._vvar_id_to_variable[varid] = variable
                self._vvar_id_to_variable_offset[varid] = offset

    def set_variable_offset(self, obj: TaggedObject | int, offset: int) -> None:
        self._variable_offsets[self._key(obj)] = offset

    def set_custom_string(self, obj: TaggedObject | int, value: bool = True) -> None:
        self._custom_strings[self._key(obj)] = value

    def set_reference_values(self, obj: TaggedObject | int, reference_values: dict[SimType, Any]) -> None:
        self._reference_values[self._key(obj)] = reference_values

    def set_reference_variable(self, obj: TaggedObject | int, variable: SimVariable | None, offset: int = 0) -> None:
        """Set the reference variable information for an AIL atom. If ``variable`` is ``None``, the reference variable information for
        this atom is cleared."""
        key = self._key(obj)
        if variable is None:
            self._reference_variables.pop(key, None)
            self._reference_variable_offsets.pop(key, None)
        else:
            self._reference_variables[key] = variable
            self._reference_variable_offsets[key] = offset

    def set_prototype(self, obj: TaggedObject | int, prototype: SimTypeFunction | None) -> None:
        """Set the call-site prototype for an AIL Call. If ``prototype`` is ``None``, the prototype information for
        this atom is cleared."""

        key = self._key(obj)
        if prototype is None:
            self._prototypes.pop(key, None)
        else:
            self._prototypes[key] = prototype

    def set_calling_convention(self, obj: TaggedObject | int, cc: SimCC | None) -> None:
        """Set the calling convention for an AIL Call. If ``cc`` is ``None``, the calling-convention information for
        this atom is cleared."""

        key = self._key(obj)
        if cc is None:
            self._calling_conventions.pop(key, None)
        else:
            self._calling_conventions[key] = cc

    def set_variant(self, obj: TaggedObject | int, variant: Any) -> None:
        """Set the enum variant for a Rust ``Let`` expression. If ``variant`` is ``None``, the variant information for
        this atom is cleared."""

        key = self._key(obj)
        if variant is None:
            self._variants.pop(key, None)
        else:
            self._variants[key] = variant

    def set_returnty(self, obj: TaggedObject | int, returnty: SimType | None) -> None:
        """Set the return type for a Rust ``FunctionLikeMacro`` call. If ``returnty`` is ``None``, the return-type
        information for this atom is cleared."""

        key = self._key(obj)
        if returnty is None:
            self._returntys.pop(key, None)
        else:
            self._returntys[key] = returnty

    def transfer(self, src: TaggedObject | int, dst: TaggedObject | int) -> None:
        """
        Copy all variable information associated with ``src`` to ``dst``. Used when an AIL atom is deep-copied to a new
        ``.idx`` (e.g. during structuring/duplication) so that the new atom keeps the same variable association.
        """

        src_key = self._key(src)
        dst_key = self._key(dst)
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
            "variables": {idx: (v.ident if v is not None else None) for idx, v in self._variables.items()},
            "variable_offsets": dict(self._variable_offsets),
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

        vm = cls()

        def _resolve(ident) -> SimVariable | None:
            return resolve_variable(ident) if ident is not None else None

        for idx, ident in data.get("variables", {}).items():
            v = _resolve(ident)
            if v is not None:
                vm._variables[int(idx)] = v
            else:
                _l.warning("Variable with ident %s could not be resolved during VariableMap deserialization", ident)
        for idx, offset in data.get("variable_offsets", {}).items():
            vm._variable_offsets[int(idx)] = offset
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
