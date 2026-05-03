add_library(iron_common STATIC stats.c)
target_include_directories(iron_common PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
