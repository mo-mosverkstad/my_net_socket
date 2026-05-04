add_library(iron_cli STATIC cli.c)
target_include_directories(iron_cli PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/common
    ${CMAKE_SOURCE_DIR}/ironstack
)
target_link_libraries(iron_cli iron_common)
