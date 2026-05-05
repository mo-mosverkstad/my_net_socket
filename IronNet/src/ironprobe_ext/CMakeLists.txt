add_executable(ironprobe-ext main.c)
target_include_directories(ironprobe-ext PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(ironreport report.c)
target_include_directories(ironreport PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/common
    ${CMAKE_SOURCE_DIR}/ironstack
    ${CMAKE_SOURCE_DIR}
)
target_link_libraries(ironreport iron_common)
