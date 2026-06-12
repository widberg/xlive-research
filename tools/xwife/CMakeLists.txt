cmake_minimum_required(VERSION 3.5)

if(${CMAKE_SOURCE_DIR} STREQUAL ${CMAKE_BINARY_DIR})
    message(FATAL_ERROR "Prevented in-tree built. Please create a build directory outside of the source code and call cmake from there")
endif()

project(xwife)

add_subdirectory(dependencies/CLI11)
add_subdirectory(dependencies/Catch2)

add_library(xwife_lib STATIC
    src/xlive_protect_data.hpp
    src/xlive_protect_data.cpp
    src/xe_keys_obfuscate.hpp
    src/xe_keys_obfuscate.cpp
    src/syncrosoft.hpp
    src/syncrosoft.cpp
    src/panorama.hpp
    src/panorama.cpp
    src/sha.hpp
    src/sha.cpp
    src/aes.hpp
    src/aes.cpp
    src/c_small_buffer.hpp
    src/c_small_buffer.cpp
    src/ops.hpp
    src/ops.cpp
)
target_include_directories(xwife_lib PUBLIC src)
target_compile_features(xwife_lib PUBLIC cxx_std_20)
set_target_properties(xwife_lib PROPERTIES
    CXX_STANDARD 20
    CXX_STANDARD_REQUIRED ON
    CXX_EXTENSIONS OFF
)

add_executable(xwife src/main.cpp)
target_link_libraries(xwife PRIVATE xwife_lib CLI11)
target_compile_features(xwife PRIVATE cxx_std_20)
set_target_properties(xwife PROPERTIES
    CXX_STANDARD 20
    CXX_STANDARD_REQUIRED ON
    CXX_EXTENSIONS OFF
)

enable_testing()

add_executable(xwife_tests tests/test_ops.cpp)
target_link_libraries(xwife_tests PRIVATE xwife_lib Catch2::Catch2)
target_compile_definitions(xwife_tests PRIVATE
    TEST_DATA_DIR="${CMAKE_CURRENT_SOURCE_DIR}/tests/data")
target_compile_features(xwife_tests PRIVATE cxx_std_20)
set_target_properties(xwife_tests PROPERTIES
    CXX_STANDARD 20
    CXX_STANDARD_REQUIRED ON
    CXX_EXTENSIONS OFF
)

list(APPEND CMAKE_MODULE_PATH ${Catch2_SOURCE_DIR}/extras)
include(Catch)
catch_discover_tests(xwife_tests)
