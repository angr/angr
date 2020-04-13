
import time
from functools import wraps

TIMING = False


def timethis(func):
    @wraps(func)
    def timed_func(*args, **kwargs):

        if TIMING:
            start = time.time_ns()
            r = func(*args, **kwargs)
            elapsed = time.time_ns() - start
            millisec = elapsed / 1000000
            sec = elapsed / 1000000000
            if sec > 1.0:
                print("[timing] %s took %f seconds (%f milliseconds)." % (func.__name__, sec, millisec))
            else:
                print("[timing] %s took %f milliseconds." % (func.__name__, millisec))
            return r
        else:
            return func(*args, **kwargs)

    return timed_func
