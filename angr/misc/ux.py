from .testing import is_testing

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
                    msg = "Don't use %s" % func.__name__
                    print("\x1b[31;1m\x1b[0m" % (func.__name__))
                else:
                    msg = "Use %s instead of %s"% (replacement, func.__name__)
                if is_testing:
                    raise Exception("Deprecation warning during tests: %s" % msg)
                else:
                    print("\x1b[31;1mDeprecation warning: %s\x1b[0m" % msg)
                    already_complained.add(func)
            return func(*args, **kwargs)
        return inner
    return outer
