import warnings


once_set = set()

def once(key):
    if key in once_set:
        return False
    else:
        once_set.add(key)
        return True

already_complained = set()


def deprecated(replacement=None):
    def outer(func):
        def inner(*args, **kwargs):
            if func not in already_complained:
                if replacement is None:
                    warnings.warn("Don't use %s" % (func.__name__), DeprecationWarning)
                else:
                    warnings.warn("Use %s instead of %s" % (replacement, func.__name__), DeprecationWarning)
                already_complained.add(func)
            return func(*args, **kwargs)
        return inner
    return outer
