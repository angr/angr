once_set = set()

def once(key):
    if key in once_set:
        return False
    else:
        once_set.add(key)
        return True

def deprecated(f, replacement=None):
    def deprecated_wrapper(*args, **kwargs):
        if replacement is not None:
            print "ERROR: FUNCTION %s IS DEPRECATED. PLEASE UPDATE YOUR CODE." % f
        else:
            print "ERROR: FUNCTION %s IS DEPRECATED. PLEASE UPDATE YOUR CODE: %s" % (f, replacement)
        return f(*args, **kwargs)
    return deprecated_wrapper
