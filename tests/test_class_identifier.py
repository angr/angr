import os
import unittest

import angr

test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "binaries", "tests")


# pylint: disable=missing-class-docstring
# pylint: disable=no-self-use
class TestClassIdentifier(unittest.TestCase):
    def test_class_identification_x86_64(self):
        p = angr.Project(os.path.join(test_location, "x86_64", "cpp_classes"), auto_load_libs=False)
        class_identifier_analysis = p.analyses.ClassIdentifier()
        classes_found = class_identifier_analysis.classes
        class_labels = []
        vtable_ptr_c = [0x403CB0, 0x403CD8]

        for class_str in classes_found:
            class_labels.append(class_str)

        assert "A" in class_labels
        assert "B" in class_labels
        assert "C" in class_labels

        for vtable_ptr in classes_found["C"].vtable_ptrs:
            assert vtable_ptr in vtable_ptr_c

        for func_addr in classes_found["C"].function_members:
            assert func_addr in [0x401262, 0x401490, 0x4014CB, 0x401512]

        for func_addr in classes_found["B"].function_members:
            assert func_addr in [0x4011EA, 0x401226, 0x4014D6]

        for func_addr in classes_found["A"].function_members:
            assert func_addr in [0x401418, 0x401454, 0x4014F4]


if __name__ == "__main__":
    unittest.main()
