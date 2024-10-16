from __future__ import annotations
import claripy

from angr.storage.memory_mixins.memory_mixin import MemoryMixin


class PermissionsMixin(MemoryMixin):
    """
    This mixin adds a permissions_bits field and properties for extracting the read/write/exec permissions. It does NOT
    add permissions checking.
    """

    def __init__(self, permissions: int | claripy.ast.BV | None = None, **kwargs):
        super().__init__(**kwargs)
        if permissions is None:
            permissions = 7
        if isinstance(permissions, int):
            permissions = claripy.BVV(permissions, 3)
        self.permission_bits = permissions

    def copy(self, memo):
        o = super().copy(memo)
        o.permission_bits = self.permission_bits
        return o

    @property
    def perm_read(self):
        return self.permission_bits & 1

    @property
    def perm_write(self):
        return self.permission_bits & 2

    @property
    def perm_exec(self):
        return self.permission_bits & 4
