add_library(iron_mon STATIC audit.c stats_json.c)
target_include_directories(iron_mon PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/common
)
target_link_libraries(iron_mon iron_common)
