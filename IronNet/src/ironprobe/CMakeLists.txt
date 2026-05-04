add_library(iron_probe STATIC probe.c)
target_include_directories(iron_probe PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/common
    ${CMAKE_SOURCE_DIR}/ironstack
    ${CMAKE_SOURCE_DIR}/ironapps
)
target_link_libraries(iron_probe iron_common)
