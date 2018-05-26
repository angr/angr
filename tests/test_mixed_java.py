import os

import angr
from angr.state_plugins.javavm_memory import SimJavaVmMemory
from angr.state_plugins.keyvalue_memory import SimKeyValueMemory
from angr.state_plugins.symbolic_memory import SimSymbolicMemory
from archinfo.arch_amd64 import ArchAMD64
from archinfo.arch_soot import (ArchSoot, SootAddressDescriptor,
                                SootMethodDescriptor)

test_location = str(os.path.join(os.path.dirname(
    os.path.realpath(__file__)), "..", "..", "binaries", "tests"))


def test_loading_of_native_libs_with_ld_path(binary_dir="1"):
    native_libs_ld_path = os.path.join(test_location,
                                       "mixed_java",
                                       binary_dir,
                                       "libs")
    jar_path = os.path.join(test_location,
                            "mixed_java",
                            binary_dir,
                            "MixedJava.jar")

    # define which libraries to load (+ the load path)
    jni_options = {
        'native_libs': ['libmixedjava.so'],
        'native_libs_ld_path': native_libs_ld_path
    }

    # information about native libraries are passed as additional options
    # of the main binary (e.g. the JAR/APK) to the project
    project = angr.Project(jar_path, main_opts=jni_options)

    # check if native library libnotfun.so was loaded
    loaded_libs_names = [
        lib.provides for lib in project.loader.all_elf_objects]
    assert 'libmixedjava.so' in loaded_libs_names


def test_loading_of_native_libs_without_ld_path(binary_dir="2"):
    # the folder of the JAR is implicitly used as an additional load path
    project = create_project(binary_dir)
    # check if native library libnotfun.so was loaded
    loaded_libs_names = [
        lib.provides for lib in project.loader.all_elf_objects]
    assert 'libmixedjava.so' in loaded_libs_names


def test_toggling_of_simstate(binary_dir="2"):
    project = create_project(binary_dir)

    state = project.factory.entry_state()
    assert state.javavm_with_jni
    assert state.javavm
    assert state.ip_is_soot_addr
    assert isinstance(state.arch, ArchSoot)
    assert isinstance(state.memory, SimJavaVmMemory)
    assert isinstance(state.registers, SimKeyValueMemory)
    assert len(state.callstack) == 2

    state.callstack.push(state.callstack.copy())
    assert len(state.callstack) == 3

    state.regs.ip = 1
    assert len(state.callstack) == 1
    assert not state.ip_is_soot_addr
    assert isinstance(state.arch, ArchAMD64)
    assert isinstance(state.memory, SimSymbolicMemory)
    assert isinstance(state.registers, SimSymbolicMemory)

    state.regs._ip = project.entry
    state.callstack.pop()
    assert len(state.callstack) == 2
    assert state.ip_is_soot_addr
    assert isinstance(state.arch, ArchSoot)
    assert isinstance(state.memory, SimJavaVmMemory)
    assert isinstance(state.registers, SimKeyValueMemory)

    state.ip = 1
    assert len(state.callstack) == 1
    assert not state.ip_is_soot_addr
    assert isinstance(state.arch, ArchAMD64)
    assert isinstance(state.memory, SimSymbolicMemory)
    assert isinstance(state.registers, SimSymbolicMemory)

    state_copy = state.copy()
    assert not state_copy.ip_is_soot_addr
    assert len(state_copy.callstack) == 1
    assert isinstance(state_copy.arch, ArchAMD64)
    assert isinstance(state_copy.memory, SimSymbolicMemory)
    assert isinstance(state_copy.registers, SimSymbolicMemory)


def test_jni_env_get_version(binary_dir="2"):
    project = create_project(binary_dir)
    last_state = get_last_state_of_method(project, "MixedJava.main")
    # check return value
    jni_version_1_8 = 0x10008
    assert_values(last_state, {'i0': jni_version_1_8}, "MixedJava.main")


def test_primitive_types(binary_dir="3"):
    project = create_project(binary_dir)

    # boolean
    method_fullname = "MixedJava.test_boolean"
    values = {'z0': 1,
              'z1': 0,
              'z2': 1,
              'z3': 0,
              'z4': 1
              }
    end_state = get_last_state_of_method(project, method_fullname)
    assert_values(end_state, values, method_fullname)

    # byte
    method_fullname = "MixedJava.test_byte"
    values = {'b5': 30,
              'b8': 0xffffff80,
              'b11': 0
              }
    end_state = get_last_state_of_method(project, method_fullname)
    assert_values(end_state, values, method_fullname)

    # char
    method_fullname = "MixedJava.test_char"
    values = {'c4': 21,
              'c6': 0,
              'c9':  1
              }
    end_state = get_last_state_of_method(project, method_fullname)
    assert_values(end_state, values, method_fullname)

    # short
    method_fullname = "MixedJava.test_short"
    values = {'s3': 0x1000,
              's0': 11,
              's5': 0xfffff000,
              's9': 0
              }
    end_state = get_last_state_of_method(project, method_fullname)
    assert_values(end_state, values, method_fullname)

    # int
    method_fullname = "MixedJava.test_int"
    values = {'i1': 0xfffffff6,
              'i3': 0,
              'i5': 0x80000001,
              'i7': 0x7fffffff
              }
    end_state = get_last_state_of_method(project, method_fullname)
    assert_values(end_state, values, method_fullname)

    # long
    method_fullname = "MixedJava.test_long"
    values = {'l1': 0xffffffffffffffff,
              'l3': 1
              }
    end_state = get_last_state_of_method(project, method_fullname)
    assert_values(end_state, values, method_fullname)

#
# Helper
#


def assert_values(state, values, method_fullname):
    for symbol_name, assert_value in values.items():
        symbol = state.memory.stack.load(symbol_name)
        val = state.solver.eval_one(symbol)
        print symbol_name + ":", "assert", hex(val), "==", hex(assert_value)
        assert val == assert_value


def create_project(binary_dir):
    jar_path = os.path.join(test_location, "mixed_java",
                            binary_dir, "MixedJava.jar")
    jni_options = {'native_libs': ['libmixedjava.so']}
    return angr.Project(jar_path, main_opts=jni_options)


def get_last_state_of_method(project, method_name):
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


def main():
    #test_loading_of_native_libs_with_ld_path()
    #test_loading_of_native_libs_without_ld_path()
    test_jni_env_get_version()
    test_primitive_types()


if __name__ == "__main__":
    main()
