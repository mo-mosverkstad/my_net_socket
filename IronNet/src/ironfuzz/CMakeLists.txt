add_library(iron_fuzz STATIC fuzz.c)
target_include_directories(iron_fuzz PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/common
)
target_link_libraries(iron_fuzz iron_common)
