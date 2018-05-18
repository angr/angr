
import os
from archinfo.arch_soot import SootMethodDescriptor, SootAddressDescriptor
import angr

"""
Tests if primitive types are passed correctly (as parameters and return values)
between the Soot and Vex engine.
"""

test_location = str(os.path.join(os.path.dirname(
    os.path.realpath(__file__)), "..", "..", "binaries", "tests"))
binary_path = os.path.join(test_location, "mixed_java",
                           "primitive_types", "MixedJava.jar")

jni_options = {'native_libs': ['libmixedjava.so']}
project = angr.Project(binary_path, main_opts=jni_options)

classes = project.loader.main_object.classes['MixedJava']
print classes


def assert_values(state, values):
    for symbol_name, assert_value in values.items():
        symbol = state.memory.stack.load(symbol_name)
        val = state.solver.eval_one(symbol)
        print symbol_name + ":", "assert", hex(val), "==", hex(assert_value)
        assert val == assert_value


def get_last_state_of_method(method_name):
    # get SootAddressDescriptor of method entry
    soot_method = next(project.loader.main_object.get_method(method_name))
    method = SootMethodDescriptor.from_soot_method(soot_method)
    addr = SootAddressDescriptor(method, 0, 0)
    # create call state
    state = project.factory.blank_state(addr=addr)
    # run until no successors exists
    # Note: this does not work if conditional branches are present
    states = [state]
    succ = states[-1].step()
    while len(succ.successors) == 1:
        states += succ
        succ = states[-1].step()
    # last state is the 'Terminator' state
    # => return the state before
    return states[-2]


def test_boolean():
    values = {'z0': 1,
              'z1': 0,
              'z2': 1,
              'z3': 0,
              'z4': 1
              }
    end_state = get_last_state_of_method("MixedJava.test_boolean")
    assert_values(end_state, values)


def test_byte():
    values = {'b5': 30,
              'b8': 0xffffff80,
              'b11': 0
              }
    end_state = get_last_state_of_method("MixedJava.test_byte")
    assert_values(end_state, values)


def test_char():
    values = {'c4': 21,
              'c6': 0,
              'c9':  1
              }
    end_state = get_last_state_of_method("MixedJava.test_char")
    assert_values(end_state, values)


def test_short():
    values = {'s3': 0x1000,
              's0': 11,
              's5': 0xfffff000,
              's9': 0
              }
    end_state = get_last_state_of_method("MixedJava.test_short")
    assert_values(end_state, values)


def test_int():
    values = {'i1': 0xfffffff6,
              'i3': 0,
              'i5': 0x80000001,
              'i7': 0x7fffffff
              }
    end_state = get_last_state_of_method("MixedJava.test_int")
    assert_values(end_state, values)


def test_long():
    values = {'l1': 0xffffffffffffffff,
              'l3': 1
              }
    end_state = get_last_state_of_method("MixedJava.test_long")
    assert_values(end_state, values)


def main():

    # logging.getLogger("angr.sim_procedure").setLevel("DEBUG")
    # logging.getLogger("angr.engines").setLevel("DEBUG")
    # logging.getLogger('angr.simos.JavaVM').setLevel("DEBUG")

    test_boolean()
    test_byte()
    test_char()
    test_short()
    test_int()
    test_long()


if __name__ == "__main__":
    main()
