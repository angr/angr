from unittest import TestCase, main
import os.path

import angr


test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "..", "binaries", "tests")


# pylint: disable=no-self-use
class CFBlanketTests(TestCase):
    """
    Test CFBlanket analysis
    """

    def test_on_object_added_callback(self):
        my_callback_artifacts = {}

        def my_callback(addr, obj):
            my_callback_artifacts[addr] = obj

        p = angr.Project(os.path.join(test_location, "x86_64", "fauxware"), load_options={"auto_load_libs": False})
        cfb = p.analyses.CFB(on_object_added=my_callback)

        addr = 0x1_00000000
        obj = "my object"
        cfb.add_obj(addr, obj)
        assert addr in my_callback_artifacts and my_callback_artifacts[addr] == obj


if __name__ == "__main__":
    main()
