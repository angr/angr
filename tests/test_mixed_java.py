import os
import angr

from archinfo.arch_soot import ArchSoot
from archinfo.arch_amd64 import ArchAMD64
from angr.state_plugins.javavm_memory import SimJavaVmMemory 
from angr.state_plugins.keyvalue_memory import SimKeyValueMemory
from angr.state_plugins.symbolic_memory import SimSymbolicMemory

test_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../../binaries/tests'))

native_libs_ld_path = os.path.join(test_location, "java_jni/")
jar_path = os.path.join(test_location, "java_jni/NotFun.jar")

# define which libraries to load (+ the load path)
jni_options = {
    'native_libs' : ['libnotfun.so'],
    'native_libs_ld_path' : native_libs_ld_path
}
# information about native libraries are passed as additional options
# of the main binary (e.g. the JAR/APK) to the project
project = angr.Project(jar_path, main_opts=jni_options)

def test_loading_of_native_libs():
    # check if native library libnotfun.so was loaded
    loaded_libs_names = [lib.provides for lib in project.loader.all_elf_objects]
    assert 'libnotfun.so' in loaded_libs_names

def test_toggling_of_simstate():

    """
    Test if the "mode" of the SimState is toggled correctly.
    """

    state = project.factory.entry_state()
    assert isinstance(state.arch, ArchSoot)
    assert isinstance(state.memory, SimJavaVmMemory)
    assert isinstance(state.registers, SimKeyValueMemory)

    state.regs.ip = 1
    assert isinstance(state.arch, ArchAMD64) 
    assert isinstance(state.memory, SimSymbolicMemory)
    assert isinstance(state.registers, SimSymbolicMemory)

    state.regs._ip = project.entry
    assert isinstance(state.arch, ArchSoot)
    assert isinstance(state.memory, SimJavaVmMemory)
    assert isinstance(state.registers, SimKeyValueMemory)

    state.ip = 1
    assert isinstance(state.arch, ArchAMD64) 
    assert isinstance(state.memory, SimSymbolicMemory)
    assert isinstance(state.registers, SimSymbolicMemory)


def main():
    test_loading_of_native_libs()
    test_toggling_of_simstate()

if __name__ == "__main__":
    main()
