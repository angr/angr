from . import MemoryMixin

class UnwrapperMixin(MemoryMixin):
    """
    This mixin processes SimActionObjects by passing on their .ast field.
    """
    def store(self, addr, data, size=None, condition=None, **kwargs):
        return super().store(_raw_ast(addr), _raw_ast(data),
            size=_raw_ast(size),
            condition=_raw_ast(condition),
            **kwargs)

    def load(self, addr, size=None, condition=None, fallback=None, **kwargs):
        return super().load(_raw_ast(addr),
            size=_raw_ast(size),
            condition=_raw_ast(condition),
            fallback=_raw_ast(fallback),
            **kwargs)

    def find(self, addr, what, max_search, default=None, **kwargs):
        return super().find(_raw_ast(addr), _raw_ast(what), max_search,
            default=_raw_ast(default),
            **kwargs)

    def copy_contents(self, dst, src, size, condition=None, **kwargs):
        return super().copy_contents(_raw_ast(dst), _raw_ast(src), _raw_ast(size), _raw_ast(condition), **kwargs)

from ...state_plugins.sim_action_object import _raw_ast
