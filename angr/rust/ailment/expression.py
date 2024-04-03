import ailment
from ailment.utils import stable_hash

from ...knowledge_plugins.cfg import MemoryData


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


class VecInitialization(ailment.statement.Statement):
    def __init__(self, idx, dst, init_values, **kwargs):
        super().__init__(idx, **kwargs)
        self.dst = dst
        self.init_values = init_values

    def __repr__(self):
        return f"vec!{self.init_values}"

    def __str__(self):
        return f"vec!{self.init_values}"

    def _hash_core(self):
        return stable_hash((VecInitialization, self.idx))

    def replace(self, old_expr, new_expr):
        raise NotImplementedError()
