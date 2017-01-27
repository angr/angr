
import os

from archinfo.arch_soot import SootAddressDescriptor, SootMethodDescriptor
import angr


def test_fauxware():
    binary_path = os.path.join("..", "..", "pysoot", "tests", "test_samples", "simple1.jar")

    proj = angr.Project(binary_path)

    simgr = proj.factory.simgr()
    main_method = next(proj.loader.main_object.main_methods)
    simgr.active[0].ip = SootAddressDescriptor(SootMethodDescriptor.from_method(main_method), 0, 0)

    simgr.explore()

    # import ipdb; ipdb.set_trace()

def main():
    test_fauxware()

if __name__ == "__main__":
    main()