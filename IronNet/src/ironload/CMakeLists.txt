add_library(iron_load STATIC load.c)
target_include_directories(iron_load PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/common
    ${CMAKE_SOURCE_DIR}/ironstack
)
target_link_libraries(iron_load iron_common)
