# pylint: disable=missing-class-docstring,disable=no-self-use
import os
import unittest

import angr

test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "binaries", "tests")


class TestFindObjectsStatic(unittest.TestCase):
    def test_object_identification_x86_64(self):
        p = angr.Project(os.path.join(test_location, "x86_64", "cpp_classes"), auto_load_libs=False)
        object_identifier_analysis = p.analyses.StaticObjectFinder()
        possible_objects_dict = object_identifier_analysis.possible_objects
        possible_constructors = object_identifier_analysis.possible_constructors
        class_labels = []

        for possible_object in possible_objects_dict.values():
            class_labels.append(possible_object.class_name)

        assert "C" in class_labels
        assert len(possible_objects_dict) == 2
        assert len(possible_constructors) == 1
        assert 0x401512 in possible_constructors
        assert len(possible_constructors[0x401512]) == 2


if __name__ == "__main__":
    unittest.main()
