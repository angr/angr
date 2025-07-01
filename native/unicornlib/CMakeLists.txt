cmake_minimum_required(VERSION 3.15)

# Setup project and standards
project(unicornlib LANGUAGES C CXX)
set (CMAKE_C_STANDARD 99)
set (CMAKE_CXX_STANDARD 11)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Check for required CMake variables
if(NOT DEFINED PYVEX_INCLUDE_PATH)
    message(FATAL_ERROR "PYVEX_INCLUDE_PATH CMake variable must be set (use -DPYVEX_INCLUDE_PATH=...)" )
endif()
if(NOT DEFINED PYVEX_LIB_PATH)
    message(FATAL_ERROR "PYVEX_LIB_PATH CMake variable must be set (use -DPYVEX_LIB_PATH=...)" )
endif()

# Add the library
add_library(unicornlib SHARED unicorn_dynamic.c sim_unicorn.cpp)
set_target_properties(unicornlib PROPERTIES OUTPUT_NAME "unicornlib")

# Set include directories and link libraries
target_include_directories(unicornlib PRIVATE vendor ${PYVEX_INCLUDE_PATH})
target_link_libraries(unicornlib PRIVATE ${PYVEX_LIB_PATH}/libpyvex.dylib)

# Install in both build and source directories to accommodate editable builds and wheels
install(TARGETS unicornlib DESTINATION ${CMAKE_SOURCE_DIR}/lib)
install(TARGETS unicornlib DESTINATION lib)
