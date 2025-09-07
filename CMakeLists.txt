cmake_minimum_required(VERSION 3.25)
project(ArenaAllocator
    VERSION 0.8.1
    LANGUAGES C)

add_subdirectory(./libsrc)

target_compile_options(ArenaAllocator
    PRIVATE
    -std=gnu23
    -Wall -Wextra -Wpedantic -pedantic
    $<$<STREQUAL:$<UPPER_CASE:${CMAKE_BUILD_TYPE}>,DEBUG>:-g -ggdb>
    $<$<STREQUAL:$<UPPER_CASE:${CMAKE_BUILD_TYPE}>,RELEASE>:-Werror -O3 -ffast-math>
)
