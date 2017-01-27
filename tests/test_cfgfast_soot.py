
import os

import angr

def test_simple1():
    # FIXME: Move simple1.jar to the binaries repo
    binary_path = os.path.join("..", "..", "pysoot", "tests", "test_samples", "simple1.jar")
    p = angr.Project(binary_path)
    cfg = p.analyses.CFGFastSoot()
    assert cfg.graph.nodes()


def test_simple2():
    # FIXME: Move simple2.jar to the binaries repo
    binary_path = os.path.join("..", "..", "pysoot", "tests", "test_samples", "simple2.jar")
    p = angr.Project(binary_path)
    cfg = p.analyses.CFGFastSoot()
    assert cfg.graph.nodes()


def main():
    test_simple1()
    test_simple2()


if __name__ == "__main__":
    main()
