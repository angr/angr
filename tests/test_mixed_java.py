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

#
# Loading
#

def test_loading_of_native_libs_with_ld_path(binary_dir="1"):
    native_libs_ld_path = os.path.join(
        test_location, "mixed_java", binary_dir, "libs"
    )
    jar_path = os.path.join(
        test_location, "mixed_java", binary_dir, "MixedJava.jar"
    )
    # define which libraries to load (+ the load path)
    jni_options = {
        'native_libs': ['libmixedjava.so'],
        'native_libs_ld_path': native_libs_ld_path
    }
    project = angr.Project(jar_path, main_opts=jni_options)
    # check if libmixedjava.so was loaded
    loaded_libs = [lib.provides for lib in project.loader.all_elf_objects]
    assert 'libmixedjava.so' in loaded_libs

def test_loading_of_native_libs_without_ld_path(binary_dir="2"):
    # the folder of the JAR is implicitly used as an additional load path
    project = create_project(binary_dir)
    # check if libmixedjava.so was loaded
    loaded_libs = [lib.provides for lib in project.loader.all_elf_objects]
    assert 'libmixedjava.so' in loaded_libs

#
# SimStates
#

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

#
# JNI Interface
#

def test_jni_env_get_version(binary_dir="2"):
    project = create_project(binary_dir)
    end_state = get_last_state_of_method(project, "MixedJava.main")
    # check return value
    jni_version_1_8 = 0x10008
    assert_values(end_state, {'i0': jni_version_1_8})

#
# Datatypes
#

def test_primitive_types(binary_dir="3"):
    project = create_project(binary_dir)
    # boolean
    values = {'z0': 1, 'z1': 0, 'z2': 1, 'z3': 0, 'z4': 1}
    end_state = get_last_state_of_method(project, "MixedJava.test_boolean")
    assert_values(end_state, values)
    # byte
    values = {'b5': 30, 'b8': 0xffffff80, 'b11': 0}
    end_state = get_last_state_of_method(project, "MixedJava.test_byte")
    assert_values(end_state, values)
    # char
    values = {'c4': 21, 'c6': 0, 'c9': 1}
    end_state = get_last_state_of_method(project, "MixedJava.test_char")
    assert_values(end_state, values)
    # short
    values = {'s3': 0x1000, 's0': 11, 's5': 0xfffff000, 's9': 0}
    end_state = get_last_state_of_method(project, "MixedJava.test_short")
    assert_values(end_state, values)
    # int
    values = {'i1': 0xfffffff6, 'i3': 0, 'i5': 0x80000001, 'i7': 0x7fffffff}
    end_state = get_last_state_of_method(project, "MixedJava.test_int")
    assert_values(end_state, values)
    # long
    values = {'l1': 0xffffffffffffffff, 'l3': 1}
    end_state = get_last_state_of_method(project, "MixedJava.test_long")
    assert_values(end_state, values)

#
# Arrays
#

#
# Arrays JNI
#

#
# Helper
#

def create_project(binary_dir):
    jar_path = os.path.join(test_location, "mixed_java",
                            binary_dir, "MixedJava.jar")
    jni_options = {'native_libs': ['libmixedjava.so']}
    return angr.Project(jar_path, main_opts=jni_options)


def assert_values(state, values):
    for symbol_name, assert_value in values.items():
        symbol = state.memory.stack.load(symbol_name)
        val = state.solver.eval_one(symbol)
        print symbol_name + ":", "assert", hex(val), "==", hex(assert_value)
        assert val == assert_value

def get_entry_state_of_method(project, method_name):
    # get SootAddressDescriptor of method entry
    soot_method = next(project.loader.main_object.get_method(method_name))
    method = SootMethodDescriptor.from_soot_method(soot_method)
    addr = SootAddressDescriptor(method, 0, 0)
    # create call state
    return project.factory.blank_state(addr=addr)

def get_last_state_of_method(project, method_name):
    state = get_entry_state_of_method(project, method_name)
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

def get_winning_paths(project, method_fullname):
    state = get_entry_state_of_method(project, method_fullname)
    simgr = project.factory.simgr(state)
    simgr.run()
    paths = simgr.deadended
    
    # winning paths output a single 'W' on stdout
    winnning_paths = []
    for pp in paths:
        stdout_packets = pp.posix.stdout.content
        read_byte, _ = stdout_packets[0]
        # a winning path is printing 'W'
        pp.state.add_constraints(read_byte == pp.state.solver.BVV(ord('W'), 8))
        if pp.satisfiable():
            winnning_paths.append(pp)

    return winnning_paths

def get_winning_path(project, method_fullname):
    winning_paths = get_winning_paths(project, method_fullname)
    assert len(winning_paths) == 1
    return winning_paths[0]


def main():
    #test_loading_of_native_libs_with_ld_path()
    #test_loading_of_native_libs_without_ld_path()
    test_jni_env_get_version()
    test_primitive_types()


if __name__ == "__main__":
    main()
