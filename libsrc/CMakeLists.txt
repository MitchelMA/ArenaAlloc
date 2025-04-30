add_library(ArenaAllocator)

file(GLOB PUBLIC_HEADERS  ./include/*.h)
file(GLOB PRIVATE_SOURCES ./private/*.c)

target_sources(ArenaAllocator
    PUBLIC
    ${PUBLIC_HEADERS}
    PRIVATE
    ${PRIVATE_SOURCES})

target_include_directories(ArenaAllocator
    PUBLIC
    ${CMAKE_CURRENT_LIST_DIR}/include)
