from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from angr.sim_type import SimType

if TYPE_CHECKING:
    from angr.ailment.tagged_object import TaggedObject
    from angr.sim_variable import SimVariable


class VariableMap:
    """
    A side container that maps the ``.idx`` of AIL :class:`Statement` and :class:`Expression` objects to
    variable-related information that used to be stored directly on the AIL objects themselves.

    The following pieces of information are tracked:

    - ``variable`` (a :class:`SimVariable`) and ``variable_offset`` (an ``int``): the variable that an AIL atom
      resolves to, and the offset into that variable.
    - ``custom_string`` (a ``bool``): whether a ``Const`` expression refers to a custom string.
    - ``reference_values`` (a ``dict`` mapping :class:`SimType` to a value): reference values associated with a
      ``Const`` expression (e.g., custom strings).
    - ``reference_variable`` (a :class:`SimVariable`) and ``reference_variable_offset`` (an ``int``): the variable
      that a constant expression references, and the offset into it. These are siblings of ``variable`` /
      ``variable_offset`` that are specifically used for constants that reference global/extern variables.

    Keys are the integer ``.idx`` values of AIL Statement/Expression objects. Because :class:`Clinic` builds one
    :class:`ailment.Manager` per function, ``.idx`` values are unique within a single function, so a VariableMap is
    scoped to one function and is stored on its :class:`DecompilationCache`.
    """

    __slots__ = (
        "_custom_strings",
        "_reference_values",
        "_reference_variable_offsets",
        "_reference_variables",
        "_variable_offsets",
        "_variables",
    )

    def __init__(self):
        self._variables: dict[int, SimVariable] = {}
        self._variable_offsets: dict[int, int] = {}
        self._custom_strings: dict[int, bool] = {}
        self._reference_values: dict[int, dict[SimType, Any]] = {}
        self._reference_variables: dict[int, SimVariable] = {}
        self._reference_variable_offsets: dict[int, int] = {}

    #
    # Key helper
    #

    @staticmethod
    def _key(obj: TaggedObject | int) -> int:
        return obj if type(obj) is int else obj.idx

    #
    # Accessors
    #

    def variable(self, obj: TaggedObject | int) -> SimVariable | None:
        return self._variables.get(self._key(obj))

    def variable_offset(self, obj: TaggedObject | int) -> int:
        return self._variable_offsets.get(self._key(obj), 0)

    def custom_string(self, obj: TaggedObject | int) -> bool:
        return self._custom_strings.get(self._key(obj), False)

    def reference_values(self, obj: TaggedObject | int) -> dict[SimType, Any] | None:
        return self._reference_values.get(self._key(obj))

    def reference_variable(self, obj: TaggedObject | int) -> SimVariable | None:
        return self._reference_variables.get(self._key(obj))

    def reference_variable_offset(self, obj: TaggedObject | int) -> int:
        return self._reference_variable_offsets.get(self._key(obj), 0)

    def has_variable(self, obj: TaggedObject | int) -> bool:
        return self._key(obj) in self._variables

    #
    # Setters
    #

    def set_variable(self, obj: TaggedObject | int, variable: SimVariable | None, offset: int = 0) -> None:
        key = self._key(obj)
        self._variables[key] = variable
        self._variable_offsets[key] = offset

    def set_variable_offset(self, obj: TaggedObject | int, offset: int) -> None:
        self._variable_offsets[self._key(obj)] = offset

    def set_custom_string(self, obj: TaggedObject | int, value: bool = True) -> None:
        self._custom_strings[self._key(obj)] = value

    def set_reference_values(self, obj: TaggedObject | int, reference_values: dict[SimType, Any]) -> None:
        self._reference_values[self._key(obj)] = reference_values

    def set_reference_variable(self, obj: TaggedObject | int, variable: SimVariable | None, offset: int = 0) -> None:
        key = self._key(obj)
        self._reference_variables[key] = variable
        self._reference_variable_offsets[key] = offset

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
        ):
            if src_key in d:
                d[dst_key] = d[src_key]

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
            ty = SimType.from_json(ty_json) if ty_json is not None else None
            if ty is None:
                continue
            d[ty] = item.get("value")
        return d

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

        def _resolve(ident):
            return resolve_variable(ident) if ident is not None else None

        for idx, ident in data.get("variables", {}).items():
            vm._variables[int(idx)] = _resolve(ident)
        for idx, offset in data.get("variable_offsets", {}).items():
            vm._variable_offsets[int(idx)] = offset
        for idx, value in data.get("custom_strings", {}).items():
            vm._custom_strings[int(idx)] = value
        for idx, items in data.get("reference_values", {}).items():
            vm._reference_values[int(idx)] = cls._reference_values_from_json(items)
        for idx, ident in data.get("reference_variables", {}).items():
            vm._reference_variables[int(idx)] = _resolve(ident)
        for idx, offset in data.get("reference_variable_offsets", {}).items():
            vm._reference_variable_offsets[int(idx)] = offset

        return vm
