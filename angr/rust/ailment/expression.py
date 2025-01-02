import ailment
from ailment.expression import Op
from ailment.tagged_object import TaggedObject
from ailment.utils import stable_hash

from angr.rust.definitions.structs import ArrayReference
from angr.rust.sim_type import RustSimStruct, EnumVariant, RustSimEnum


class String(ailment.Const):
    def __init__(self, idx, variable, value, bits, decoded_str, is_heap_str=False, **kwargs):
        super().__init__(idx, variable, value, bits, **kwargs)

        self.decoded_str = decoded_str
        self.is_heap_str = is_heap_str

    @property
    def size(self):
        return self.bits // 8

    @property
    def length(self):
        return len(self.decoded_str)

    def __repr__(self):
        return str(self)

    def __str__(self):
        return f'"{self.decoded_str}"'

    def copy(self) -> "String":
        return String(self.idx, self.variable, self.value, self.bits, self.decoded_str, **self.tags)


class StringLiteral(ailment.Expression):
    def __init__(self, idx, data, bits, **kwargs):
        super().__init__(idx, 0, **kwargs)
        self.data = data
        self._bits = bits

    @property
    def size(self):
        return self.bits // 8

    @property
    def bits(self):
        return self._bits

    def __repr__(self):
        return str(self)

    def __str__(self):
        return f'"{self.data}"'

    __hash__ = TaggedObject.__hash__

    def _hash_core(self):
        return stable_hash(self.data)

    def likes(self, other):
        return type(self) is type(other) and self.data == other.data


class Array(ailment.Expression):
    def __init__(self, idx, elements, array_type: ArrayReference, **kwargs):
        super().__init__(idx, (max(ele.depth for ele in elements) if len(elements) else 0) + 1, **kwargs)
        self.elements = elements
        self.type = array_type

    @property
    def size(self):
        return self.type.size // 8

    @property
    def bits(self):
        return self.type.size

    @property
    def length(self):
        return len(self.elements)

    def __repr__(self):
        return str(self)

    def __str__(self):
        return str(self.elements)

    __hash__ = TaggedObject.__hash__

    def _hash_core(self):
        return stable_hash((tuple(self.elements), self.type))

    def likes(self, other):
        return type(self) is type(other) and self.type == other.type and (self.elements == other.elements)


class Enum(ailment.Expression):
    def __init__(self, idx, associated_exprs, variant: EnumVariant, enum_type: RustSimEnum, **kwargs):
        super().__init__(
            idx, (max(ele.depth for ele in associated_exprs) if len(associated_exprs) else 0) + 1, **kwargs
        )
        self.associated_exprs = associated_exprs
        self.variant = variant
        self.type = enum_type

    @property
    def size(self):
        return self.type.size // 8

    @property
    def bits(self):
        return self.type.size

    def __repr__(self):
        return str(self)

    def __str__(self):
        return f"{self.variant.name}({str(self.associated_exprs)})"

    __hash__ = TaggedObject.__hash__

    def _hash_core(self):
        return stable_hash((tuple(self.associated_exprs), self.variant, self.type))

    def likes(self, other):
        return (
            type(self) is type(other)
            and self.type == other.type
            and self.associated_exprs == other.associated_exprs
            and self.variant == other.variant
        )


class Struct(ailment.Expression):
    def __init__(self, idx, fields, struct_type: RustSimStruct, **kwargs):
        super().__init__(idx, (max(field.depth for field in fields.values()) if len(fields) else 0) + 1, **kwargs)
        self.fields = fields
        self.field_names = {}
        self.field_offsets = {}
        for name, offset in struct_type.offsets.items():
            self.field_names[offset] = name
            self.field_offsets[name] = offset
        self.type = struct_type

    def get_field(self, name):
        if name in self.field_offsets:
            offset = self.field_offsets[name]
            return self.fields.get(offset, None)
        return None

    @property
    def size(self):
        return self.type.size // 8

    @property
    def bits(self):
        return self.type.size

    def __repr__(self):
        return str(self)

    def __str__(self):
        return self.type.name + " " + str(self.fields)

    __hash__ = TaggedObject.__hash__

    def _hash_core(self):
        return stable_hash((tuple(self.fields.keys()), tuple(self.fields.values()), self.type))

    def likes(self, other):
        return (
            type(self) is type(other)
            and self.type == other.type
            and self.fields.keys() == other.fields.keys()
            and all(self.fields[k].likes(other.fields[k]) for k in self.fields)
        )

    def matches(self, other):
        return (
            type(self) is type(other)
            and self.type == other.type
            and self.fields.keys() == other.fields.keys()
            and all(self.fields[k].matches(other.fields[k]) for k in self.fields)
        )


class Let(Op):
    __slots__ = ("variant", "defs", "src", "bits")

    def __init__(self, idx, variant, defs, src, **kwargs):
        super().__init__(idx, depth=src.depth + 1, op="let", **kwargs)
        self.variant = variant
        self.defs = defs
        self.src = src

        self.bits = src.bits

    def __repr__(self):
        return str(self)

    def __str__(self):
        return f"let {self.variant.name}(_) = {self.src}"

    __hash__ = TaggedObject.__hash__

    def _hash_core(self):
        return stable_hash((self.variant, self.src))

    def likes(self, other):
        return type(self) is type(other) and self.variant == other.variant and self.src == other.src

    def matches(self, other):
        return type(self) is type(other) and self.variant == other.variant and self.src == other.src
