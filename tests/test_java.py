import os
import unittest

import angr
from angr.storage.memory_mixins import JavaVmMemory, DefaultMemory, KeyValueMemory
from angr.engines.soot.values import SimSootValue_ArrayRef, SimSootValue_ThisRef
from angr.engines.soot.method_dispatcher import resolve_method
from archinfo.arch_amd64 import ArchAMD64
from archinfo.arch_soot import (
    ArchSoot,
    SootAddressDescriptor,
    SootMethodDescriptor,
    SootArgument,
    SootAddressTerminator,
)
from claripy.backends.backend_smtlib_solvers import z3str_popen  # noqa: F401

try:
    import pysoot
except ModuleNotFoundError:
    pysoot = None

file_dir = os.path.dirname(os.path.realpath(__file__))
test_location = os.path.join(file_dir, "..", "..", "binaries", "tests", "java")


@unittest.skipUnless(pysoot, "pysoot not available")
def test_fauxware():
    # create project
    binary_path = os.path.join(test_location, "fauxware_java_jni", "fauxware.jar")
    jni_options = {"jni_libs": ["libfauxware.so"]}
    project = angr.Project(binary_path, main_opts=jni_options)
    entry = project.factory.entry_state()
    simgr = project.factory.simgr(entry)

    # find path to `accepted()` method
    accepted_method = SootMethodDescriptor.from_string("Fauxware.accepted()").address()
    simgr.explore(find=lambda s: s.addr == accepted_method)

    state = simgr.found[0]

    # eval password
    cmd_line_args = project.simos.get_cmd_line_args(state)
    password = state.solver.eval(cmd_line_args[0])
    assert password == "SOSNEAKY"


def test_apk_loading():
    sdk_path = os.path.join(os.path.expanduser("~"), "Android/Sdk/platforms/")
    if not os.path.exists(sdk_path):
        print("cannot run test_apk_loading since there is no Android SDK folder")
        return

    loading_opts = {
        "android_sdk": sdk_path,
        "entry_point": "com.example.antoniob.android1.MainActivity.onCreate",
        "entry_point_params": ("android.os.Bundle",),
    }
    project = angr.Project(os.path.join(test_location, "android1.apk"), main_opts=loading_opts, auto_load_libs=False)

    blank_state = project.factory.blank_state()
    a1 = SimSootValue_ThisRef.new_object(blank_state, "com.example.antoniob.android1.MainActivity")
    a2 = SimSootValue_ThisRef.new_object(blank_state, "android.os.Bundle", symbolic=True)
    args = [SootArgument(arg, arg.type) for arg in [a1, a2]]
    entry = project.factory.entry_state(args=args)

    simgr = project.factory.simgr(entry)
    simgr.step()
    simgr.step()
    assert simgr.active[0].addr.block_idx == 0
    assert simgr.active[0].addr.stmt_idx == 3
    simgr.run()
    assert len(simgr.deadended) == 1
    assert type(simgr.deadended[0].addr) is SootAddressTerminator


#
# Command line arguments
#


@unittest.skipUnless(pysoot, "pysoot not available")
def test_cmd_line_args():
    project = create_project("cmd_line_args", load_native_libs=False)
    entry = project.factory.entry_state()
    simgr = project.factory.simgr(entry)
    simgr.run()
    assert len(simgr.deadended) == 2
    state1, state2 = tuple(simgr.deadended)

    # get symbol of args[0] from memory
    args = state1.globals["cmd_line_args"]
    args0_arrref = SimSootValue_ArrayRef(args, 0)
    args0_strref = state1.memory.load(args0_arrref)
    args0_strval = state1.memory.load(args0_strref)

    # eval args[0] on both states
    str1 = state1.solver.eval(args0_strval)
    str2 = state2.solver.eval(args0_strval)
    assert "secret_value" in [str1, str2]


#
# JNI Version Information
#


@unittest.skipUnless(pysoot, "pysoot not available")
def test_jni_version_information():
    project = create_project("jni_version_information")

    run_method(project=project, method="MixedJava.test_jni_get_version", assert_locals={"i0": 0x10008})


#
# JNI Global and Local References
#


@unittest.skipUnless(pysoot, "pysoot not available")
def test_jni_global_and_local_refs():
    project = create_project("jni_global_and_local_refs")

    assertions = {"global refs dict": lambda state: (state.jni_references.global_refs == {})}
    run_method(
        project=project, method="MixedJava.test_jni_global_refs", assert_locals={"i0": 0xA}, assertions=assertions
    )


#
# JNI Object Operations
#


def test_jni_object_operations():
    project = create_project("jni_object_operations")

    run_method(project=project, method="MixedJava.test_jni_alloc_object", assert_locals={"i0": 0})

    run_method(project=project, method="MixedJava.test_jni_new_object", assert_locals={"i0": 1})

    run_method(project=project, method="MixedJava.test_jni_new_subclass_object", assert_locals={"i0": 2})

    run_method(
        project=project, method="MixedJava.test_jni_isinstanceof", assert_locals={"i0": 1, "i1": 1, "i2": 0, "i3": 1}
    )

    run_method(project=project, method="MixedJava.test_jni_issameobject", assert_locals={"i0": 0, "i1": 1})


#
# JNI String Operations
#


def test_jni_string_operations():
    project = create_project("jni_string_operations")

    assertions = {
        "1st string": lambda state: (state.solver.eval_one(load_string(state, "r0")) == "mum"),
        "2nd string": lambda state: (state.solver.eval_one(load_string(state, "r1")) == "himum!"),
    }
    run_method(
        project=project,
        method="MixedJava.test_jni_string_operations",
        assert_locals={"i0": 0x3, "i1": 0x6},
        assertions=assertions,
    )


#
# JNI Field Access
#


def test_jni_field_access():
    project = create_project("jni_field_access")

    run_method(
        project=project,
        method="MixedJava.test_static_field_access_basic",
        assert_locals={"i0": 0x0, "i1": 0x1, "i2": 0xA, "i3": 0xB, "i4": 0x7, "i5": 0xB, "i6": 0x0, "i7": 0x9},
    )

    run_method(project=project, method="MixedJava.test_jni_static_field_access", assert_locals={"i0": 0, "i1": 5})

    run_method(
        project=project,
        method="MixedJava.test_jni_static_field_access_subclass",
        assert_locals={"i0": 1, "i1": 10, "i2": 30, "i3": 1},
    )

    run_method(
        project=project,
        method="MixedJava.test_instance_field_access_0",
        assert_locals={"i0": 0, "i1": 10, "i2": 5, "i3": 5},
    )

    run_method(
        project=project,
        method="MixedJava.test_instance_field_access_1",
        assert_locals={"i0": 0, "i1": 1, "i2": 10, "i3": 4, "i4": 4, "i5": 1},
    )


#
# JNI Method Calls
#


@unittest.skipUnless(pysoot, "pysoot not available")
def test_jni_method_calls():
    project = create_project("jni_method_calls")

    run_method(project=project, method="MixedJava.test_jni_non_virtual_instance_method_call", assert_locals={"i0": 5})

    run_method(
        project=project, method="MixedJava.test_jni_instance_method_calls_basic", assert_locals={"i0": 7, "i1": 7}
    )

    run_method(
        project=project, method="MixedJava.test_jni_instance_method_calls_subclass", assert_locals={"i0": 2, "i1": 2}
    )

    run_method(
        project=project,
        method="MixedJava.test_jni_instance_method_calls_shared_method_id",
        assert_locals={"i0": 8, "i1": 2},
    )

    run_method(project=project, method="MixedJava.test_jni_instance_method_calls_args", assert_locals={"i0": 11})

    run_method(project=project, method="MixedJava.test_jni_static_method_call", assert_locals={"i0": 10})

    run_method(project=project, method="MixedJava.test_jni_static_method_call_return_obj", assert_locals={"i0": 7})


#
# JNI Primitive Datatypes
#


@unittest.skipUnless(pysoot, "pysoot not available")
def test_jni_primitive_datatypes():
    project = create_project("jni_primitive_datatypes")

    run_method(
        project=project, method="MixedJava.test_boolean", assert_locals={"z0": 1, "z1": 0, "z2": 1, "z3": 0, "z4": 1}
    )

    run_method(project=project, method="MixedJava.test_byte", assert_locals={"b5": 30, "b8": 0xFFFFFF80, "b11": 0})

    run_method(project=project, method="MixedJava.test_char", assert_locals={"c4": 21, "c6": 0, "c9": 1})

    run_method(
        project=project,
        method="MixedJava.test_short",
        assert_locals={"s3": 0x1000, "s5": 0xFFFFF000, "s0": 11, "s9": 0},
    )

    run_method(
        project=project,
        method="MixedJava.test_int",
        assert_locals={"i1": 0xFFFFFFF6, "i3": 0, "i5": 0x80000001, "i7": 0x7FFFFFFF},
    )

    run_method(project=project, method="MixedJava.test_long", assert_locals={"l1": 0xFFFFFFFFFFFFFFFF, "l3": 1})


@unittest.skipUnless(pysoot, "pysoot not available")
def test_jni_object_arrays():
    project = create_project("jni_object_array_operations")

    run_method(project=project, method="MixedJava.test_jni_access_object_array", assert_locals={"i0": 7})

    run_method(project=project, method="MixedJava.test_jni_new_object_array", assert_locals={"i0": 10})


#
# JNI Array Operations
#


@unittest.skipUnless(pysoot, "pysoot not available")
def test_jni_array_operations():
    project = create_project("jni_array_operations")

    # test_jni_newarray
    run_method(
        project=project,
        method="MixedJava.test_jni_newarray",
        assert_locals={"i0": 0, "i1": 1, "i2": 2, "i3": 3, "i4": 4},
    )

    # test_jni_getarrayregion
    state = run_method(project=project, method="MixedJava.test_jni_getarrayregion")
    a = load_value_from_stack(state, "i1")
    state.solver.add(a == 15)
    idx = state.posix.stdin.content[0][0]
    assert state.solver.eval_one(idx) == 7

    # test_jni_setarrayregion1
    run_method(
        project=project,
        method="MixedJava.test_jni_setarrayregion1",
        assert_locals={"i0": 0, "i1": 3, "i2": 2, "i3": 1, "i4": 4},
    )

    # test_jni_setarrayregion2
    state = run_method(project=project, method="MixedJava.test_jni_setarrayregion2")
    a = load_value_from_stack(state, "i1")
    state.solver.add(a == 2)
    idx = state.posix.stdin.content[0][0]
    idx_value = state.solver.eval_one(idx)
    assert idx_value == 0

    # test_jni_setarrayregion2
    state = run_method(project=project, method="MixedJava.test_jni_setarrayregion2")
    a = load_value_from_stack(state, "i1")
    state.solver.add(a == 0)
    idx = state.posix.stdin.content[0][0]
    idx_value = state.solver.eval_exact(idx, 2)
    assert 1 in idx_value
    assert 2 in idx_value
    assert 3 not in idx_value

    # test_jni_getarrayelements_symbolic
    winning_path = get_winning_path(project=project, method_fullname="MixedJava.test_jni_getarrayelements_symbolic")
    stdin_packets = winning_path.posix.stdin.content
    idx = winning_path.solver.eval_one(stdin_packets[0][0])
    min_length = winning_path.solver.min(stdin_packets[1][0])
    assert idx == 223
    assert min_length == 224

    # test_jni_releasearrayelements
    run_method(
        project=project,
        method="MixedJava.test_jni_releasearrayelments",
        assert_locals={"i0": 4, "i1": 3, "i2": 2, "i3": 1, "i4": 0},
    )

    # test_jni_getarrayelements_and_releasearrayelements
    run_method(
        project=project,
        method="MixedJava.test_jni_getarrayelements_and_releasearrayelements",
        assert_locals={
            "c9": 0xFFFF,
            "c14": 0x0000,
            "b5": 0x0000007F,
            "b10": 0xFFFFFF80,
            "s6": 0x00007FFF,
            "s11": 0xFFFF8000,
            "i7": 0x7FFFFFFF,
            "i12": 0x80000000,
            "l8": 0x7FFFFFFFFFFFFFFF,
            "l13": 0x8000000000000000,
        },
    )

    # test_jni_getarraylength
    state = run_method(project=project, method="MixedJava.test_jni_getarraylength")
    a = state.memory.stack.load("i3")
    assert state.solver.eval(a) == 10
    b = state.memory.stack.load("i4")
    assert state.solver.min(b) == 0
    assert state.solver.max(b) == 255


#
# Method Calls
#


@unittest.skipUnless(pysoot, "pysoot not available")
def test_method_calls():
    project = create_project("method_calls", load_native_libs=False)

    run_method(
        project=project,
        method="MixedJava.test_instance_method_calls",
        assert_locals={"i0": 0, "i1": 1, "i2": 1, "i3": 2, "i4": 2, "i5": 2},
    )

    run_method(
        project=project,
        method="MixedJava.test_static_method_calls_0",
        assert_locals={"i0": 0, "i1": 1, "i2": 2, "i3": 2},
    )

    run_method(
        project=project,
        method="MixedJava.test_static_method_calls_1",
        assert_locals={"i0": 0, "i1": 0, "i2": 1, "i3": 2, "i4": 2, "i5": 2},
    )

    run_method(project=project, method="MixedJava.test_special_invoke_0", assert_locals={"i0": 3})

    run_method(project=project, method="MixedJava.test_special_invoke_1", assert_locals={"i0": 4})


#
# Array Operations
#


@unittest.skipUnless(pysoot, "pysoot not available")
def test_array_operations():
    project = create_project("array_operations", load_native_libs=False)

    # test_basic_array_operations
    run_method(
        project=project,
        method="MixedJava.test_basic_array_operations",
        assert_locals={"i1": 0, "i2": 1, "i3": 2, "i4": 3, "i5": 4, "i6": 5, "i7": 2, "i8": 0},
    )

    # test_symbolic_array_read
    winning_path = get_winning_path(project=project, method_fullname="MixedJava.test_symbolic_array_read")
    stdin_packets = winning_path.posix.stdin.content
    input_char, _ = stdin_packets[0]
    solutions = winning_path.solver.eval_upto(input_char, 2)
    assert ord("A") in solutions
    assert ord("C") in solutions

    # test_symbolic_array_write
    winning_path = get_winning_path(project=project, method_fullname="MixedJava.test_symbolic_array_write")
    stdin_packets = winning_path.posix.stdin.content
    idx_symbol, _ = stdin_packets[0]
    val_symbol, _ = stdin_packets[1]
    winning_path.solver.add(val_symbol != 0)  # exclude trivial solution
    idx = winning_path.solver.eval(idx_symbol)
    val = winning_path.solver.eval(val_symbol)
    assert idx == 73
    assert val == 53

    # test_symbolic_array_length
    winning_path = get_winning_path(project=project, method_fullname="MixedJava.test_symbolic_array_length")
    stdin_packets = winning_path.posix.stdin.content
    input_char, _ = stdin_packets[0]
    solution = winning_path.solver.eval(input_char)
    assert solution == ord("F")

    # test_index_of_of_bound0
    state = run_method(project=project, method="MixedJava.test_index_of_of_bound0")
    array_len = load_value_from_stack(state, "i1")
    assert state.solver.min(array_len) == 0
    assert state.solver.max(array_len) == 255

    # test_index_of_of_bound1
    state = run_method(project=project, method="MixedJava.test_index_of_of_bound1")
    array_len = load_value_from_stack(state, "i1")
    assert state.solver.min(array_len) == 101
    assert state.solver.max(array_len) == 255

    # test_index_of_of_bound2
    state = run_method(project=project, method="MixedJava.test_index_of_of_bound2")
    assert load_value_from_stack(state, "i1") is not None
    assert load_value_from_stack(state, "i2") is None
    assert load_value_from_stack(state, "i3") is None
    assert load_value_from_stack(state, "i4") is not None
    assert load_value_from_stack(state, "i5") is None

    # test_index_of_of_bound3
    state = run_method(project=project, method="MixedJava.test_index_of_of_bound3")
    assert load_value_from_stack(state, "i1") is not None
    assert load_value_from_stack(state, "i2") is not None
    assert load_value_from_stack(state, "i3") is None
    assert load_value_from_stack(state, "i4") is not None
    assert load_value_from_stack(state, "i5") is None

    # test_index_of_of_bound4
    state = run_method(project=project, method="MixedJava.test_index_of_of_bound4")
    assert load_value_from_stack(state, "i1") is not None
    assert load_value_from_stack(state, "i2") is not None
    assert load_value_from_stack(state, "i3") is None

    # test_index_of_of_bound5
    state = run_method(project=project, method="MixedJava.test_index_of_of_bound5")
    assert load_value_from_stack(state, "i1") is not None
    assert load_value_from_stack(state, "i2") is not None
    assert load_value_from_stack(state, "i3") is None


#
# MultiArray Operations
#


@unittest.skipUnless(pysoot, "pysoot not available")
def test_multiarray_operations():
    project = create_project("multiarray_operations", load_native_libs=False)

    run_method(project=project, method="MixedJava.basic_multiarray_ops", assert_locals={"d1": 4})


#
# Loading
#


@unittest.skipUnless(pysoot, "pysoot not available")
def test_loading():
    # Test1: test loading with load path
    native_libs_ld_path = os.path.join(test_location, "misc", "loading1", "libs")
    jar_path = os.path.join(test_location, "misc", "loading1", "mixedjava.jar")
    # define which libraries to load (+ the load path)
    jni_options = {"jni_libs": ["libmixedjava.so"], "jni_libs_ld_path": native_libs_ld_path}
    project = angr.Project(jar_path, main_opts=jni_options, auto_load_libs=True)
    # check if libmixedjava.so was loaded
    loaded_libs = [lib.provides for lib in project.loader.all_elf_objects]
    assert "libmixedjava.so" in loaded_libs

    # Test 2: test loading without load path
    # => the folder of the JAR is implicitly used as an additional load path
    binary_dir = os.path.join(test_location, "misc", "loading2")
    project = create_project(binary_dir)
    # check if libmixedjava.so was loaded
    loaded_libs = [lib.provides for lib in project.loader.all_elf_objects]
    assert "libmixedjava.so" in loaded_libs


#
# SimStates
#


@unittest.skipUnless(pysoot, "pysoot not available")
def test_toggling_of_simstate():
    binary_dir = os.path.join(test_location, "misc", "simstates")
    project = create_project(binary_dir)

    state = project.factory.entry_state()
    assert state.ip_is_soot_addr
    assert isinstance(state.arch, ArchSoot)
    assert isinstance(state.memory, JavaVmMemory)
    assert isinstance(state.registers, KeyValueMemory)

    state.regs.ip = 1
    assert not state.ip_is_soot_addr
    assert isinstance(state.arch, ArchAMD64)
    assert isinstance(state.memory, DefaultMemory)
    assert isinstance(state.registers, DefaultMemory)

    state.regs._ip = project.entry

    assert state.ip_is_soot_addr
    assert isinstance(state.arch, ArchSoot)
    assert isinstance(state.memory, JavaVmMemory)
    assert isinstance(state.registers, KeyValueMemory)

    state.ip = 1
    assert not state.ip_is_soot_addr
    assert isinstance(state.arch, ArchAMD64)
    assert isinstance(state.memory, DefaultMemory)
    assert isinstance(state.registers, DefaultMemory)

    state_copy = state.copy()
    assert not state_copy.ip_is_soot_addr
    assert isinstance(state_copy.arch, ArchAMD64)
    assert isinstance(state_copy.memory, DefaultMemory)
    assert isinstance(state_copy.registers, DefaultMemory)


@unittest.skipUnless(pysoot, "pysoot not available")
def test_object_tracking():
    binary_dir = os.path.join(test_location, "object_tracking")
    project = create_project(binary_dir, load_native_libs=False)
    bootstrap_state = project.factory.blank_state(addr=SootAddressTerminator())
    mylib_object = SimSootValue_ThisRef.new_object(bootstrap_state, "MyLib", symbolic=True, init_object=False)

    soot_method = resolve_method(
        bootstrap_state, "testGetterAndSetterConcrete", "MixedJava", ("mylib.MyLib",), init_class=False
    ).address()

    call_state = project.factory.call_state(
        soot_method,
        SootArgument(mylib_object, mylib_object.type, is_this_ref=False),
        base_state=bootstrap_state,
        ret_addr=SootAddressTerminator(),
    )

    call_state.options.add(angr.options.JAVA_IDENTIFY_GETTER_SETTER)
    call_state.options.add(angr.options.JAVA_TRACK_ATTRIBUTES)

    simgr = project.factory.simgr(call_state)
    simgr.run()

    assert len(simgr.deadended) == 1

    final_state = simgr.deadended[0]

    assert final_state.solver.eval(mylib_object.get_field(final_state, "myInt", "int")) == 1
    assert final_state.solver.eval(mylib_object.get_field(final_state, "myShort", "short")) == 1
    assert final_state.solver.eval(mylib_object.get_field(final_state, "myChar", "char")) == ord("c")
    assert final_state.solver.eval(mylib_object.get_field(final_state, "myLong", "long")) == 2
    assert final_state.solver.eval(mylib_object.get_field(final_state, "myFloat", "float")) == 1.5
    assert final_state.solver.eval(mylib_object.get_field(final_state, "myDouble", "double")) == 1.5
    string_ref = mylib_object.get_field(final_state, "myString", "java.lang.String")
    assert final_state.solver.eval(final_state.memory.load(string_ref)) == "Hello!"
    array_ref = mylib_object.get_field(final_state, "myArray", "int[]")
    assert final_state.solver.eval(array_ref.size) == 3
    object_ref = mylib_object.get_field(final_state, "myObject", "java.lang.Object")
    assert final_state.solver.eval(object_ref.get_field(final_state, "a", "int")) == 1

    assert ("myInt", "int") in mylib_object.attributes
    assert ("myChar", "char") in mylib_object.attributes
    assert ("myShort", "short") in mylib_object.attributes
    assert ("myLong", "long") in mylib_object.attributes
    assert ("myFloat", "float") in mylib_object.attributes
    assert ("myDouble", "double") in mylib_object.attributes
    assert ("myString", "java.lang.String") in mylib_object.attributes
    assert ("myArray", "int[]") in mylib_object.attributes
    assert ("myObject", "java.lang.Object") in mylib_object.attributes


#
# Helper
#


def run_method(project, method, assert_locals=None, assertions=None):
    end_state = get_last_state_of_method(project, method)
    # print_java_memory(end_state)

    if assert_locals:
        for symbol_name, assert_value in assert_locals.items():
            symbol = load_value_from_stack(end_state, symbol_name)
            val = end_state.solver.eval(symbol)
            assert val == assert_value

    if assertions:
        for _, test in assertions.items():
            assert test(end_state)

    return end_state


# def print_java_memory(state):
#     print "\n##### STACK ##########" + "#"*60
#     print state.memory.stack
#     print "\n##### HEAP ###########" + "#"*60
#     print state.memory.heap
#     print "\n##### VM STATIC TABLE " + "#"*60
#     print state.memory.vm_static_table
#     print


@unittest.skipUnless(pysoot, "pysoot not available")
def create_project(binary_dir, load_native_libs=True):
    jar_path = os.path.join(test_location, binary_dir, "mixedjava.jar")
    if load_native_libs:
        jni_options = {"jni_libs": ["libmixedjava.so"]}
        project = angr.Project(jar_path, main_opts=jni_options)
    else:
        project = angr.Project(jar_path)
    return project


def load_string(state, local_name):
    str_ref = load_value_from_stack(state, local_name)
    return state.memory.load(str_ref)


def load_value_from_stack(state, symbol_name):
    try:
        return state.memory.stack.load(symbol_name)
    except KeyError:
        return None


def get_entry_state_of_method(project, method_fullname):
    # get SootAddressDescriptor of method entry
    soot_method = project.loader.main_object.get_soot_method(method_fullname)
    method = SootMethodDescriptor.from_soot_method(soot_method)
    addr = SootAddressDescriptor(method, 0, 0)
    # create call state
    return project.factory.blank_state(addr=addr, add_options={angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY})


def get_last_state_of_method(project, method_fullname):
    state = get_entry_state_of_method(project, method_fullname)
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
        pp.solver.add(read_byte == pp.solver.BVV(ord("W"), 8))
        if pp.satisfiable():
            winnning_paths.append(pp)

    return winnning_paths


def get_winning_path(project, method_fullname):
    winning_paths = get_winning_paths(project, method_fullname)
    assert len(winning_paths) != 0
    assert len(winning_paths) == 1
    return winning_paths[0]


def main():
    for k, v in list(globals().items()):
        if k.startswith("test_") and callable(v):
            v()


if __name__ == "__main__":
    # import logging
    # logging.getLogger('cle.backends.soot').setLevel('DEBUG')
    # logging.getLogger('cle.backends.apk').setLevel('DEBUG')
    # logging.getLogger('cle.backends.jar').setLevel('DEBUG')

    # logging.getLogger("angr").setLevel("DEBUG")

    # logging.getLogger("angr.state_plugins").setLevel("INFO")
    # logging.getLogger('angr.state_plugins.javavm_memory').setLevel("DEBUG")
    # logging.getLogger('angr.state_plugins.jni_references').setLevel("DEBUG")
    # logging.getLogger("angr.state_plugins.javavm_classloader").setLevel("DEBUG")

    # logging.getLogger('archinfo.arch_soot').setLevel("DEBUG")
    # logging.getLogger('angr.procedures.java_jni').setLevel("DEBUG")
    # logging.getLogger("angr.sim_procedure").setLevel("DEBUG")
    # logging.getLogger("angr.engines").setLevel("DEBUG")
    # logging.getLogger('angr.simos.JavaVM').setLevel("DEBUG")
    # logging.getLogger('angr.engines.vex').setLevel("DEBUG")
    #
    main()
