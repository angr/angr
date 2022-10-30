cmake_minimum_required (VERSION 3.8)

project ("angr_c")

add_subdirectory ("angr_c")

set(PYBIND11_PYTHON_VERSION 3)
set(PYBIND11_FINDPYTHON ON)

add_subdirectory (extern/pybind11)

pybind11_add_module (angr_native
	angr_c/angr_c.cpp
	angr_c/block.cpp
	angr_c/memories.cpp
	angr_c/memory_mixins/sim_memory_object.cpp
	angr_c/memory_mixins/pages/decomposer.cpp
	angr_c/memory_mixins/memory_mixin_base.cpp
	angr_c/vex_lifter.cpp
)

target_include_directories (angr_c PRIVATE "F:/angr/vex/pub/")
target_include_directories (angr_native PRIVATE "F:/angr/vex/pub/")
target_compile_features (angr_native PRIVATE cxx_std_20)
