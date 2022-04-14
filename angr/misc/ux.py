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
                    print("\x1b[31;1mDeprecation warning: Don't use %s\x1b[0m" % (func.__name__))
                else:
                    print("\x1b[31;1mDeprecation warning: Use %s instead of %s\x1b[0m" % (replacement, func.__name__))
                already_complained.add(func)
            return func(*args, **kwargs)
        return inner
    return outer
