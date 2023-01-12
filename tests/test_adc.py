import os
import unittest

import angr

test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "binaries", "tests")


# pylint: disable=missing-class-docstring
# pylint: disable=no-self-use
class TestAdc(unittest.TestCase):
    def test_adc_i386(self):
        proj = angr.Project(os.path.join(test_location, "i386", "test_adc"), load_options={"auto_load_libs": False})

        start = 0x804840B
        end = 0x804842E

        state = proj.factory.blank_state(
            addr=start,
            remove_options={
                angr.options.LAZY_SOLVES,
            },
            add_options={angr.options.SYMBOLIC_WRITE_ADDRESSES},
        )

        pg = proj.factory.simulation_manager(state, veritesting=False)
        pg.explore(find=end)

        found_state = pg.found[0]
        result = found_state.solver.eval(found_state.regs.eax)
        assert result == 0x1

    def test_all(self):
        self.test_adc_i386()


if __name__ == "__main__":
    unittest.main()
