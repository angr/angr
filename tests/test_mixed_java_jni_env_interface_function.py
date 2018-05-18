

import os
from archinfo.arch_soot import SootMethodDescriptor, SootAddressDescriptor
import angr

"""
Test the interaction of native code with the JVM through the JNI interface functions.

Lifted Java code:
//<pysoot.sootir.soot_class.SootClass object at 0x7fa3138e2830>
 class MixedJava extends java.lang.Object{
	//<pysoot.sootir.soot_method.SootMethod object at 0x7fa30880ac08>
	void <init>(){
		//<Block 0 [0], 3 statements>
		r0 <- @this[MixedJava]
		r0.<init>() [specialinvoke java.lang.Object.<init>()]
		return null
	}
	
	//<pysoot.sootir.soot_method.SootMethod object at 0x7fa3088181b8>
	static native int get_version(){
	}
	
	//<pysoot.sootir.soot_method.SootMethod object at 0x7fa308818410>
	public static void main(java.lang.String[]){
		//<Block 0 [0], 3 statements>
		r0 <- @parameter0[java.lang.String[]]
		i0 = get_version() [staticinvoke MixedJava.get_version()]
		return null
	}
	
	//<pysoot.sootir.soot_method.SootMethod object at 0x7fa308818488>
	static void <clinit>(){
		//<Block 0 [0], 2 statements>
		loadLibrary('"MixedJava"') [staticinvoke java.lang.System.loadLibrary(java.lang.String)]
		return null
	}
	
}
"""

test_location = str(os.path.join(os.path.dirname(
    os.path.realpath(__file__)), "..", "..", "binaries", "tests"))
binary_path = os.path.join(test_location, "mixed_java",
                           "jni_env_function_call", "MixedJava.jar")

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


def test_jni_env_get_version():
    state = project.factory.entry_state()
    # run until no successors exists
    # Note: this does not work if conditional branches are present
    states = [state]
    succ = states[-1].step()
    while len(succ.successors) == 1:
        states += succ
        succ = states[-1].step()
    # last state is the 'Terminator' state
    # => return the state before
    last_state = states[-2]
    # check return value
    jni_version_1_8 = 0x10008
    assert_values(last_state, {'i0': jni_version_1_8})


def main():

    # logging.getLogger("angr.sim_procedure").setLevel("DEBUG")
    # logging.getLogger("angr.engines").setLevel("DEBUG")
    # logging.getLogger('angr.simos.JavaVM').setLevel("DEBUG")

    test_jni_env_get_version()


if __name__ == "__main__":
    main()
