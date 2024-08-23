# pylint:disable=no-member,global-statement
from __future__ import annotations
import os
import time
from functools import wraps
from collections import defaultdict

TIMING = os.environ.get("TIMING", "").lower() not in {"", "no", "0", "false"}
PRINT = os.environ.get("PRINT", "").lower() not in {"", "no", "0", "false"}
TIME_DISTRIBUTION = False

total_time = defaultdict(float)
time_distribution = defaultdict(list)
depth = 0


def timethis(func):
    @wraps(func)
    def timed_func(*args, **kwargs):
        if TIMING:

            def _t():
                return time.perf_counter_ns() / 1000000

            global depth
            depth += 1

            start = _t()
            r = func(*args, **kwargs)
            millisec = _t() - start
            sec = millisec / 1000
            if PRINT:
                indent = " " * ((depth - 1) * 2)
                if sec > 1.0:
                    print(f"[timing] {indent}{func.__name__} took {sec:f} seconds ({millisec:f} milliseconds).")
                else:
                    print(f"[timing] {indent}{func.__name__} took {millisec:f} milliseconds.")
            total_time[func] += millisec
            if TIME_DISTRIBUTION:
                time_distribution[func].append(millisec)
            depth -= 1
            return r
        return func(*args, **kwargs)

    return timed_func
