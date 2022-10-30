cmake_minimum_required (VERSION 3.8)

add_library (angr_c SHARED
	"memory_mixins/data_normalization_mixin.hpp"
	"py_call_super.h"
	"py_call_super.c"
	"memory_mixins/paged_memory_mixin.hpp"
	"memory_mixins/page.hpp"
	"memory_mixins/memory_mixin_base.cpp"
	"memory_mixins/memory_mixin_base.hpp"
	"angr_c.cpp"
	"memories.cpp"
	"angr_c.hpp"
	"memory_mixins/decomposer.hpp"
	"memory_mixins/decomposer.cpp"
	"memory_mixins/endness.hpp"
	"memory_mixins/sim_memory_object.hpp"
	"memory_mixins/sim_memory_object.cpp"
	"memory_mixins/cooperation.cpp"
	"block.cpp"
	"block.hpp"
	"vex_lifter.hpp"
	"vex_lifter.cpp"
	"lru_cache.hpp"
	"memory_mixins/size_concretization_mixin.hpp"
	"memory_mixins/size_normalization_mixin.hpp"
	"memory_mixins/address_concretization_mixin.hpp")

set_target_properties(${PROJECT_NAME} PROPERTIES CXX_STANDARD 20)

if (DEFINED CMAKE_LIBRARY_NAME)
	set_target_properties(${PROJECT_NAME} PROPERTIES OUTPUT_NAME ${CMAKE_LIBRARY_NAME})
	set_target_properties(${PROJECT_NAME} PROPERTIES SUFFIX "")
endif()

# Here is the trick
## update the environment with VIRTUAL_ENV variable (mimic the activate script)
# set (ENV{VIRTUAL_ENV} "C:/Users/Fish/venvs/angr")
## change the context of the search
set (Python3_FIND_VIRTUALENV FIRST)
## unset Python3_EXECUTABLE because it is also an input variable (see documentation, Artifacts Specification section)
unset (Python3_EXECUTABLE)
unset (Python_EXECUTABLE)
## Launch a new search
find_package (Python COMPONENTS Interpreter Development)
find_package (Python3 COMPONENTS Interpreter Development)

include_directories(${Python3_INCLUDE_DIRS})
link_directories(${Python3_LIBRARY_DIRS})
target_link_libraries(angr_c ${Python3_LIBRARIES})

include_directories ("F:/angr/vex/pub/")
set(INCLUDE_DIRS "F:/angr/vex/pub/")
link_directories ("F:/angr/vex/")
include_directories ("F:/angr/vex/pub")
target_link_libraries(angr_c "F:/angr/vex/libvex.lib")
target_include_directories(angr_c PRIVATE "F:/angr/vex/pub")

add_compile_definitions (PYBIND11_PYTHON_VERSION=3.10)

# TODO: Get rid of the following lines
#message(STATUS "${Python_FOUND}")
#message(STATUS "${Python_LIBRARY_DIRS}")
#message(STATUS "${Python_LIBRARIES}")
#message(STATUS "${Python_INCLUDE_DIRS}")

# For IntelliSense
include_directories ("D:/My Program Files/Python310/include/")
include_directories (${angr_c_SOURCE_DIR}/extern/pybind11/include)
include_directories ("F:/angr/vex/pub/")


get_property(dirs DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR} PROPERTY INCLUDE_DIRECTORIES)
foreach(dir ${dirs})
  message(STATUS "dir='${dir}'")
endforeach()