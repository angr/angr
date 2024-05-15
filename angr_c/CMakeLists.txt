cmake_minimum_required (VERSION 3.15...3.27)

project ("angr_c")

#
# https://discourse.cmake.org/t/possible-to-create-a-python-virtual-env-from-cmake-and-then-find-it-with-findpython3/1132
#
# Here is the trick
## update the environment with VIRTUAL_ENV variable (mimic the activate script)
set (ENV{VIRTUAL_ENV} "C:/Users/Fish/venvs/angr")
## change the context of the search
set (Python_FIND_VIRTUALENV FIRST)
set (Python3_FIND_VIRTUALENV FIRST)
## unset Python3_EXECUTABLE because it is also an input variable (see documentation, Artifacts Specification section)
unset (Python3_EXECUTABLE)
unset (Python_EXECUTABLE)
## Launch a new search
find_package (Python 3.8 COMPONENTS Interpreter Development.Module REQUIRED)

# TODO: Get rid of the following lines
message(STATUS "${Python_FOUND}")
message(STATUS "${Python_INTERPRETER_ID}")
message(STATUS "${Python_VERSION}")
message(STATUS "${Python_LIBRARY_DIRS}")
message(STATUS "${Python_LIBRARIES}")
message(STATUS "${Python_INCLUDE_DIRS}")
message(STATUS "${Python_SOSABI}")

if (NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Choose the type of build." FORCE)
  set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS "Debug" "Release" "MinSizeRel" "RelWithDebInfo")
endif()

add_subdirectory (${CMAKE_CURRENT_SOURCE_DIR}/extern/nanobind)

nanobind_add_module (angr_c
	angr_c/angr_c.cpp
	angr_c/block.cpp
	angr_c/memories.cpp
	angr_c/memory_mixins/sim_memory_object.cpp
	angr_c/memory_mixins/pages/decomposer.cpp
	angr_c/memory_mixins/memory_mixin_base.cpp
	angr_c/vex_lifter.cpp
)

include_directories(${Python_INCLUDE_DIRS})
link_directories(${Python_LIBRARY_DIRS})

target_include_directories (angr_c PRIVATE "F:/angr/vex/pub/")
target_compile_features (angr_c PRIVATE cxx_std_20)
