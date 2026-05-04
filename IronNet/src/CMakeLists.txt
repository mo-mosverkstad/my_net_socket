cmake_minimum_required(VERSION 3.20)
project(ironnet VERSION 0.1.0 LANGUAGES C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Build type defaults to Debug
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug)
endif()

# Compiler warnings
add_compile_options(
    -Wall -Wextra -Wpedantic
    -Wno-unused-parameter
)

# AddressSanitizer for Debug builds
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_compile_options(-fsanitize=address -fno-omit-frame-pointer)
    add_link_options(-fsanitize=address)
endif()

# Common include path
include_directories(${CMAKE_SOURCE_DIR}/common)

# Enable testing
enable_testing()

# Subdirectories
add_subdirectory(common)
add_subdirectory(ironctl)
add_subdirectory(ironstack)
add_subdirectory(ironmon)
add_subdirectory(ironapps)
add_subdirectory(tests)
