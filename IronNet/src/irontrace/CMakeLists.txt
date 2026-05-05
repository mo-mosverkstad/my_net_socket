add_library(iron_trace STATIC trace.c)
target_include_directories(iron_trace PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/common
)
target_link_libraries(iron_trace iron_common)
