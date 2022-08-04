# pylint:disable=no-member
import sys
import time
from functools import wraps
from collections import defaultdict

TIMING = False
PRINT = False
TIME_DISTRIBUTION = False

total_time = defaultdict(float)
time_distribution = defaultdict(list)


def timethis(func):
    @wraps(func)
    def timed_func(*args, **kwargs):

        if TIMING:
            if sys.version_info >= (3,7):
                _t = lambda: time.perf_counter_ns() / 1000000
            else:
                _t = lambda: time.time() * 1000
            start = _t()
            r = func(*args, **kwargs)
            millisec = _t() - start
            sec = millisec / 1000
            if PRINT:
                if sec > 1.0:
                    print("[timing] %s took %f seconds (%f milliseconds)." % (func.__name__, sec, millisec))
                else:
                    print("[timing] %s took %f milliseconds." % (func.__name__, millisec))
            total_time[func] += millisec
            if TIME_DISTRIBUTION:
                time_distribution[func].append(millisec)
            return r
        else:
            return func(*args, **kwargs)

    return timed_func
