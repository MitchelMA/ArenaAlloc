file(GLOB TOP_LEVEL_SOURCES *.c)
file(GLOB TOP_LEVEL_HEADERS *.h)

add_executable(ArenaAllocator
  ${TOP_LEVEL_HEADERS}
  ${TOP_LEVEL_SOURCES})
