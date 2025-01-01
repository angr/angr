# pylint:disable=no-member,global-statement
from __future__ import annotations
import os
import time
from functools import wraps
from collections import defaultdict

TIMING = os.environ.get("TIMING", "").lower() not in {"", "no", "0", "false"}
PRINT = os.environ.get("PRINT", "").lower() not in {"", "no", "0", "false"}
TIME_DISTRIBUTION = os.environ.get("TIMING_DIST", "").lower() not in {"", "no", "0", "false"}

total_time = defaultdict(float)
time_distribution = defaultdict(list)
depth = 0


def print_timing_total():
    sorted_keys = sorted(time_distribution.keys(), key=lambda x: sum(time_distribution[x]), reverse=True)
    for func in sorted_keys:
        millisec = sum(time_distribution[func])
        sec = millisec / 1000
        if sec > 1.0:
            print(f"[timing] {func.__name__}: {sec} seconds.")
        else:
            print(f"[timing] {func.__name__}: {millisec} milliseconds.")

        # list top-ten slowest calls
        sorted_calls = sorted(time_distribution[func], reverse=True)
        print("[timing]   Slowest top 10:")
        for idx, call in enumerate(sorted_calls[:10]):
            print(f"[timing]     {idx + 1}: {call} ms")


def _t():
    return time.perf_counter_ns() / 1000000


def _on_func_return(func, start: float) -> None:
    global depth

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


def timethis(func):
    @wraps(func)
    def timed_func(*args, **kwargs):
        if TIMING:
            global depth

            depth += 1
            start = _t()
            r = None
            try:
                r = func(*args, **kwargs)
            except Exception:
                _on_func_return(func, start)
                raise

            _on_func_return(func, start)
            return r
        return func(*args, **kwargs)

    return timed_func
