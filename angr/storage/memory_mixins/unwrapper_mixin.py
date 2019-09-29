class UnwrapperMixin:
    def store(self, addr, data, size=None, condition=None, **kwargs):
        return super().store(_raw_ast(addr), _raw_ast(data), None if size is None else _raw_ast(size), None if condition is None else _raw_ast(condition), **kwargs)

    def store_cases(self, addr, contents, conditions, fallback=None, **kwargs):
        return super().store_cases(_raw_ast(addr), _raw_ast(contents), _raw_ast(conditions), None if fallback is None else _raw_ast(fallback), **kwargs)

    def load(self, addr, size, condition=None, fallback=None, **kwargs):
        return super().load(_raw_ast(addr), _raw_ast(size), None if condition is None else _raw_ast(condition), None if fallback is None else _raw_ast(fallback), **kwargs)

    def find(self, addr, what, default=None, **kwargs):
        return super().find(_raw_ast(addr), _raw_ast(what), None if default is None else _raw_ast(default), **kwargs)

    def copy_contents(self, dst, src, size, condition=None, **kwargs):
        return super().copy_contents(_raw_ast(dst), _raw_ast(src), _raw_ast(size), None if condition is None else _raw_ast(condition), **kwargs)

from ...state_plugins.sim_action_object import _raw_ast
