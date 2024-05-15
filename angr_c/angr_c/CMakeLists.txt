cmake_minimum_required (VERSION 3.15...3.27)

add_library (angr_c SHARED
	"memory_mixins/data_normalization_mixin.hpp"
	"py_call_super.h"
	"py_call_super.c"
	"memory_mixins/paged_memory_mixin.hpp"
	"memory_mixins/pages/page.hpp"
	"memory_mixins/memory_mixin_base.cpp"
	"memory_mixins/memory_mixin_base.hpp"
	"angr_c.cpp"
	"memories.cpp"
	"angr_c.hpp"
	"memory_mixins/pages/decomposer.hpp"
	"memory_mixins/pages/decomposer.cpp"
	"memory_mixins/endness.hpp"
	"memory_mixins/sim_memory_object.hpp"
	"memory_mixins/sim_memory_object.cpp"
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

include_directories ("F:/angr/vex/pub/")
set(INCLUDE_DIRS "F:/angr/vex/pub/")
link_directories ("F:/angr/vex/")
include_directories ("F:/angr/vex/pub")
target_link_libraries(angr_c "F:/angr/vex/libvex.lib")
target_include_directories(angr_c PRIVATE "F:/angr/vex/pub")

# TODO: Get rid of the following lines
message(STATUS "${Python_FOUND}")
message(STATUS "${Python_LIBRARY_DIRS}")
message(STATUS "${Python_LIBRARIES}")
message(STATUS "${Python_INCLUDE_DIRS}")

# For IntelliSense
include_directories ("D:/My Program Files/Python311/include/")
include_directories (${angr_c_SOURCE_DIR}/extern/nanobind/include)
include_directories ("F:/angr/vex/pub/")


get_property(dirs DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR} PROPERTY INCLUDE_DIRECTORIES)
foreach(dir ${dirs})
  message(STATUS "dir='${dir}'")
endforeach()