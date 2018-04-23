import os
import angr

self_dir = os.path.dirname(os.path.realpath(__file__))

def test_loading_of_native_libs():

    binary_dir = os.path.join(self_dir, "..", "..", "angr-doc", "examples", "java_mixed_ictf")

    jar_path = os.path.join(binary_dir, "service.jar")
    native_libs_path = os.path.join(binary_dir, "native_libs")

    # define which libraries to load (+ the load path)
    jni_options = {
        'native_libs' : ['libnotfun.so'],
        'native_libs_ld_path' : native_libs_path
    }
    # information about native libraries are passed as additional options
    # of the main binary (e.g. the JAR/APK) to the project
    proj = angr.Project(jar_path, main_opts=jni_options)

    # check if native library libnotfun.so was loaded
    loaded_libs_names = [lib.provides for lib in proj.loader.all_elf_objects]
    assert 'libnotfun.so' in loaded_libs_names

def main():
    test_loading_of_native_libs()

if __name__ == "__main__":
    main()
