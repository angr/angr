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
    # AIL .idx values are NOT unique per object: ailment deliberately reuses an atom's .idx when rewriting
    # expressions (e.g. a Const operand can share the .idx of the BinaryOp it lives in). Keying purely by .idx would
    # therefore conflate distinct co-existing atoms. We key by (idx, class-name) instead, which matches AIL's own
    # notion of identity (``__eq__`` requires equal type and idx) while still being preserved by ``copy()`` and
    # transferable across ``deep_copy()``.

    @staticmethod
    def _key(obj: TaggedObject | tuple) -> tuple:
        return obj if type(obj) is tuple else (obj.idx, type(obj).__name__)

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

    @staticmethod
    def _encode_key(key: tuple) -> str:
        # key is (idx, class-name); encode as "<idx>:<class-name>" so it can be a JSON object key.
        return f"{key[0]}:{key[1]}"

    @staticmethod
    def _decode_key(s: str) -> tuple:
        idx, _, cls = s.partition(":")
        return (int(idx), cls)

    def to_json(self) -> dict[str, Any]:
        """
        Serialize this VariableMap to a JSON-compatible object.

        Variables are referenced by their ``.ident`` (reference-by-ident); they must be resolved back to
        :class:`SimVariable` objects via a resolver in :meth:`from_json`. Keys are encoded as ``"<idx>:<class-name>"``.
        """

        ek = self._encode_key
        return {
            "variables": {ek(k): (v.ident if v is not None else None) for k, v in self._variables.items()},
            "variable_offsets": {ek(k): v for k, v in self._variable_offsets.items()},
            "custom_strings": {ek(k): v for k, v in self._custom_strings.items()},
            "reference_values": {ek(k): self._reference_values_to_json(d) for k, d in self._reference_values.items()},
            "reference_variables": {
                ek(k): (v.ident if v is not None else None) for k, v in self._reference_variables.items()
            },
            "reference_variable_offsets": {ek(k): v for k, v in self._reference_variable_offsets.items()},
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
        dk = cls._decode_key

        def _resolve(ident):
            return resolve_variable(ident) if ident is not None else None

        for k, ident in data.get("variables", {}).items():
            vm._variables[dk(k)] = _resolve(ident)
        for k, offset in data.get("variable_offsets", {}).items():
            vm._variable_offsets[dk(k)] = offset
        for k, value in data.get("custom_strings", {}).items():
            vm._custom_strings[dk(k)] = value
        for k, items in data.get("reference_values", {}).items():
            vm._reference_values[dk(k)] = cls._reference_values_from_json(items)
        for k, ident in data.get("reference_variables", {}).items():
            vm._reference_variables[dk(k)] = _resolve(ident)
        for k, offset in data.get("reference_variable_offsets", {}).items():
            vm._reference_variable_offsets[dk(k)] = offset

        return vm
