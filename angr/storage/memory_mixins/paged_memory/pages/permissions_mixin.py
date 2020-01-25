from angr.storage.memory_mixins import MemoryMixin

class PermissionsMixin(MemoryMixin):
    """
    This mixin adds a permissions field and properties for extracting the read/write/exec permissions. It does NOT add
    permissions checking.
    """
    def __init__(self, permissions=None, **kwargs):
        super().__init__(**kwargs)
        self.permissions = permissions

    @property
    def perm_read(self):
        return self.permissions & 1

    @property
    def perm_write(self):
        return self.permissions & 2

    @property
    def perm_exec(self):
        return self.permissions & 4
