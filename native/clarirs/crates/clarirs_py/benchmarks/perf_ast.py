from __future__ import annotations

import claripy
from claripy.ast.base import Base


class MyAnnotation(claripy.Annotation):
    def __init__(self, value):
        self.value = value

    def __repr__(self):
        return f"MyAnnotation({self.value})"


def make_asts() -> list[Base]:
    results: list[Base] = []

    # Make a lot of BVS
    results.extend([claripy.BVS(str(i), 32) for i in range(1000)])

    # Make a lot of BVV
    results.extend([claripy.BVV(i, 32) for i in range(1000)])

    # Make a lot of And
    results.extend([claripy.And(claripy.BVS(str(i), 32), claripy.BVV(i, 32)) for i in range(1000)])

    # Make a lot of Or
    results.extend([claripy.Or(claripy.BVS(str(i), 32), claripy.BVV(i, 32)) for i in range(1000)])

    # Make a lot of FPS
    results.extend([claripy.FPS(str(i), claripy.FSORT_DOUBLE) for i in range(1000)])

    # Make a lot of FPV
    results.extend([claripy.FPV(i, claripy.FSORT_DOUBLE) for i in range(1000)])

    # Annotate!
    # for i in range(100):
    #     for j in range(10):
    #         results[i] = results[i].append_annotation(MyAnnotation(j))

    return results

def test_perf_ast():
    for i in range(1000):
        make_asts()

test_perf_ast()
