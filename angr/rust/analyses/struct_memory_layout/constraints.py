from abc import abstractmethod, ABC

from angr.ailment.utils import stable_hash
from angr.rust.sim_type import RustSimStruct, RustSimType


def _resolve_possible_struct_field_types(struct_ty: RustSimStruct, offset, size):
    offsets = struct_ty.offsets
    result = set()
    for field_name, field_ty in struct_ty.fields.items():
        field_offset = offsets[field_name]
        field_size = field_ty.size // 8
        if field_offset <= offset < field_offset + field_size:
            if field_offset == offset and field_size == size:
                result.add(field_ty)
            if isinstance(field_ty, RustSimStruct):
                result |= _resolve_possible_struct_field_types(field_ty, offset - field_offset, size)
    return result


class Constraint(ABC):

    @abstractmethod
    def satisfy(self, ty: RustSimStruct) -> bool:
        pass


class IsConstraint(Constraint):

    def __init__(self, offset, size, ty_cls):
        self.offset = offset
        self.size = size
        self.ty_cls = ty_cls

    def __repr__(self):
        return f"field_{self.offset} is {self.ty_cls.__name__}"

    def __hash__(self):
        return stable_hash((self.offset, self.size, self.ty_cls))

    def __eq__(self, other):
        return (
            type(self) is type(other)
            and self.offset == other.offset
            and self.size == other.size
            and self.ty_cls == other.ty_cls
        )

    def satisfy(self, struct_ty) -> bool:
        possible_types = _resolve_possible_struct_field_types(struct_ty, self.offset, self.size)
        return any(ty.__class__ is self.ty_cls for ty in possible_types)


class IsNotConstraint(Constraint):

    def __init__(self, offset, size, ty_cls):
        self.offset = offset
        self.size = size
        self.ty_cls = ty_cls

    def __repr__(self):
        return f"field_{self.offset} is not {self.ty_cls.__name__}"

    def __hash__(self):
        return stable_hash((self.offset, self.size, self.ty_cls))

    def __eq__(self, other):
        return (
            type(self) is type(other)
            and self.offset == other.offset
            and self.size == other.size
            and self.ty_cls == other.ty_cls
        )

    def satisfy(self, struct_ty) -> bool:
        possible_types = _resolve_possible_struct_field_types(struct_ty, self.offset, self.size)
        return all(ty.__class__ is not self.ty_cls for ty in possible_types)
