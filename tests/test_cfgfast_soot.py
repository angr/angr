import os
import angr

test_location = os.path.join(os.path.dirname(os.path.realpath(str(__file__))), '..', '..', 'binaries', 'tests')

def test_simple1():
    binary_path = os.path.join(test_location, "java", "simple1.jar")
    p = angr.Project(binary_path, main_opts={'entry_point': 'simple1.Class1.main'})
    cfg = p.analyses.CFGFastSoot()
    assert cfg.graph.nodes()


def test_simple2():
    binary_path = os.path.join(test_location, "java", "simple2.jar")
    p = angr.Project(binary_path, main_opts={'entry_point': 'simple2.Class1.main'})
    cfg = p.analyses.CFGFastSoot()
    assert cfg.graph.nodes()


def main():
    test_simple1()
    test_simple2()

if __name__ == "__main__":
    main()
