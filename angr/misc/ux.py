from __future__ import annotations
import warnings


once_set = set()


def once(key):
    if key in once_set:
        return False
    once_set.add(key)
    return True


already_complained = set()


def deprecated(replacement=None):
    def outer(func):
        def inner(*args, **kwargs):
            if func not in already_complained:
                if replacement is None:
                    warnings.warn(f"Don't use {func.__name__}", DeprecationWarning, stacklevel=1)
                else:
                    warnings.warn(f"Use {replacement} instead of {func.__name__}", DeprecationWarning, stacklevel=1)
                already_complained.add(func)
            return func(*args, **kwargs)

        return inner

    return outer
