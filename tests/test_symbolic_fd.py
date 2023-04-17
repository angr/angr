# pylint:disable=missing-class-docstring,no-self-use
import os
import unittest
import angr


test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "binaries", "tests")


def find(s):
    return s.posix.dumps(1) == b"c0de\n"


def avoid(s):
    return s.posix.dumps(1) == b"nothing\n"


class TestSymbolicFd(unittest.TestCase):
    def test_symbolic_fd(self):
        project = angr.Project(os.path.join(test_location, "x86_64", "symbolic_fd"))

        for method_name in ("stat_test", "fstat_test", "open_test", "fopen_test", "fdopen_test"):
            addr = project.loader.find_symbol(method_name).rebased_addr

            # all files exist
            state = project.factory.blank_state(addr=addr)
            state.options["ALL_FILES_EXIST"] = True
            simgr = project.factory.simgr(state)
            while simgr.active != []:
                simgr.explore(find=find, avoid=avoid)
            assert simgr.avoid != [] and simgr.found == [], f"{method_name}: got {simgr.avoid} and {simgr.found}"

            # any file might exist
            state = project.factory.blank_state(addr=addr)
            state.options["ALL_FILES_EXIST"] = False
            state.options["ANY_FILE_MIGHT_EXIST"] = True
            simgr = project.factory.simgr(state)
            while simgr.active != []:
                simgr.explore(find=find, avoid=avoid)
            assert simgr.avoid != [] and simgr.found != [], f"{method_name}: got {simgr.avoid} and {simgr.found}"

            # no file exists
            state = project.factory.blank_state(addr=addr)
            state.options["ALL_FILES_EXIST"] = False
            state.options["ANY_FILE_MIGHT_EXIST"] = False
            simgr = project.factory.simgr(state)
            while simgr.active != []:
                simgr.explore(find=find, avoid=avoid)
            assert simgr.avoid == [] and simgr.found != [], f"{method_name}: got {simgr.avoid} and {simgr.found}"


if __name__ == "__main__":
    unittest.main()
