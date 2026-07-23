from __future__ import annotations

import logging
from dataclasses import dataclass
from math import gcd

l = logging.getLogger(name=__name__)


class MemoryRegion:
    """
    The base class of all abstract memory regions that pointer-shape descriptors are attached to.
    """

    __slots__ = ()


@dataclass(frozen=True)
class GlobalRegion(MemoryRegion):
    """
    A global memory region identified by the address of its base (e.g., the address of a global table).
    """

    addr: int

    def __repr__(self):
        return f"Global({self.addr:#x})"


@dataclass(frozen=True)
class StackRegion(MemoryRegion):
    """
    A stack memory region identified by the owning function and the stack offset of its base.
    """

    func_addr: int
    sp_offset: int

    def __repr__(self):
        return f"Stack({self.func_addr:#x}, {self.sp_offset})"


@dataclass(frozen=True)
class HeapRegion(MemoryRegion):
    """
    A heap memory region identified by the instruction address of the allocation call site.
    """

    callsite: int

    def __repr__(self):
        return f"Heap({self.callsite:#x})"


@dataclass(frozen=True)
class UnknownRegion(MemoryRegion):
    """
    A memory region of unknown location, e.g., the region behind a pointer-typed function parameter. It is identified
    by the function it appears in and an arbitrary (but unique within the function) token.
    """

    func_addr: int
    token: int | str

    def __repr__(self):
        return f"Unknown({self.func_addr:#x}, {self.token})"


class FieldAccess:
    """
    Describes accesses to a single field (constant byte offset) of a memory region.
    """

    __slots__ = ("is_code_pointer", "size", "stored_values")

    def __init__(self, size: int | None = None, is_code_pointer: bool = False, stored_values: set[int] | None = None):
        self.size = size
        self.is_code_pointer = is_code_pointer
        self.stored_values: set[int] = stored_values if stored_values is not None else set()

    def merge(self, other: FieldAccess) -> bool:
        """
        Merge another FieldAccess into this one. Returns True if anything changed.
        """
        changed = False
        if other.size is not None and (self.size is None or other.size > self.size):
            self.size = other.size
            changed = True
        if other.is_code_pointer and not self.is_code_pointer:
            self.is_code_pointer = True
            changed = True
        if not other.stored_values <= self.stored_values:
            self.stored_values |= other.stored_values
            changed = True
        return changed

    def __repr__(self):
        vals = ", ".join(f"{v:#x}" for v in sorted(self.stored_values))
        return f"FieldAccess(size={self.size}, code_ptr={self.is_code_pointer}, values={{{vals}}})"


class PointerShapeDescriptor:
    """
    Describes the shape of a memory object (struct, array, table, ...) that one or more pointers point to: which
    fields are accessed, which concrete code pointers are stored where, and the element stride for indexed accesses.
    """

    __slots__ = ("alloc_size", "fields", "indexed", "region", "stride")

    def __init__(self, region: MemoryRegion):
        self.region = region
        self.fields: dict[int, FieldAccess] = {}
        self.stride: int | None = None
        # True if we have seen at least one indexed access (base + idx * scale) against this region, even if the
        # scale was not recoverable
        self.indexed: bool = False
        # total allocation size, when known (e.g., from a malloc()/calloc() call site with concrete arguments)
        self.alloc_size: int | None = None

    @property
    def inferred_size(self) -> int | None:
        """
        The inferred struct/element size: the stride when the region is accessed in an indexed fashion, otherwise
        the maximum accessed offset plus the size of that access.
        """
        if self.stride is not None:
            return self.stride
        if self.fields:
            return max(off + (fa.size or 1) for off, fa in self.fields.items())
        return None

    def field(self, offset: int) -> FieldAccess:
        """
        Get (or create) the FieldAccess record at the given offset.
        """
        fa = self.fields.get(offset)
        if fa is None:
            fa = FieldAccess()
            self.fields[offset] = fa
        return fa

    def normalize_offset(self, offset: int) -> int:
        """
        Map an access offset into a field offset within one element, using the stride when it is known.
        """
        if self.stride is not None and self.stride > 0:
            return offset % self.stride
        return offset

    def set_stride(self, stride: int | None) -> bool:
        """
        Record (or widen) the element stride. Conflicting strides are widened to their GCD. Returns True if the
        descriptor changed.
        """
        changed = False
        if not self.indexed:
            self.indexed = True
            changed = True
        if stride is None or stride <= 0:
            return changed
        if self.stride is None:
            self.stride = stride
            return True
        if self.stride != stride:
            new_stride = gcd(self.stride, stride)
            if new_stride != self.stride:
                self.stride = new_stride
                changed = True
        return changed

    def merge(self, other: PointerShapeDescriptor) -> bool:
        """
        Merge another descriptor into this one. Returns True if anything changed.
        """
        changed = False
        if other.indexed:
            changed |= self.set_stride(other.stride)
        for off, fa in other.fields.items():
            noff = self.normalize_offset(off)
            existing = self.fields.get(noff)
            if existing is None:
                self.fields[noff] = FieldAccess(
                    size=fa.size, is_code_pointer=fa.is_code_pointer, stored_values=set(fa.stored_values)
                )
                changed = True
            else:
                changed |= existing.merge(fa)
        if other.alloc_size is not None and (self.alloc_size is None or other.alloc_size > self.alloc_size):
            self.alloc_size = other.alloc_size
            changed = True
        return changed

    @staticmethod
    def union(a: PointerShapeDescriptor, b: PointerShapeDescriptor) -> PointerShapeDescriptor:
        """
        Return a new descriptor that is the union of two descriptors. The region of the first descriptor is kept.
        """
        result = PointerShapeDescriptor(a.region)
        result.merge(a)
        result.merge(b)
        return result

    def __repr__(self):
        fields = ", ".join(f"{off}: {fa!r}" for off, fa in sorted(self.fields.items()))
        return (
            f"PointerShapeDescriptor({self.region!r}, stride={self.stride}, indexed={self.indexed}, "
            f"size={self.inferred_size}, fields={{{fields}}})"
        )


#
# ranking used to pick union-find representatives: prefer the most concrete region kind
#
_REGION_RANK = {
    GlobalRegion: 0,
    StackRegion: 1,
    HeapRegion: 2,
    UnknownRegion: 3,
}


class DescriptorStore:
    """
    Stores pointer-shape descriptors keyed by memory region, with union-find-based aliasing: regions that are found
    to alias each other (e.g., a caller's stack struct and a callee's pointer parameter) are unioned, and their
    descriptors are merged into the representative's descriptor.
    """

    def __init__(self):
        self._parent: dict[MemoryRegion, MemoryRegion] = {}
        self._descriptors: dict[MemoryRegion, PointerShapeDescriptor] = {}

    def find(self, region: MemoryRegion) -> MemoryRegion:
        """
        Find the representative region for the given region.
        """
        if region not in self._parent:
            self._parent[region] = region
            return region
        root = region
        while self._parent[root] is not root:
            root = self._parent[root]
        # path compression
        while self._parent[region] is not root:
            region, self._parent[region] = self._parent[region], root
        return root

    def descriptor(self, region: MemoryRegion) -> PointerShapeDescriptor:
        """
        Get (or create) the descriptor of the representative region of the given region.
        """
        rep = self.find(region)
        desc = self._descriptors.get(rep)
        if desc is None:
            desc = PointerShapeDescriptor(rep)
            self._descriptors[rep] = desc
        return desc

    def get(self, region: MemoryRegion) -> PointerShapeDescriptor | None:
        """
        Get the descriptor of the representative region of the given region, or None if it does not exist.
        """
        return self._descriptors.get(self.find(region))

    def union(self, a: MemoryRegion, b: MemoryRegion) -> bool:
        """
        Union the two regions (they alias each other) and merge their descriptors. Returns True if anything changed.
        """
        rep_a = self.find(a)
        rep_b = self.find(b)
        if rep_a is rep_b or rep_a == rep_b:
            return False
        # prefer the most concrete region as the representative
        if _REGION_RANK.get(type(rep_b), 4) < _REGION_RANK.get(type(rep_a), 4):
            rep_a, rep_b = rep_b, rep_a
        self._parent[rep_b] = rep_a
        desc_a = self.descriptor(rep_a)
        desc_b = self._descriptors.pop(rep_b, None)
        if desc_b is not None:
            desc_a.merge(desc_b)
        return True

    def items(self):
        """
        Iterate over (representative region, descriptor) pairs.
        """
        return self._descriptors.items()

    def __iter__(self):
        return iter(self._descriptors)

    def __len__(self):
        return len(self._descriptors)

    def __repr__(self):
        return f"<DescriptorStore with {len(self._descriptors)} descriptors>"
