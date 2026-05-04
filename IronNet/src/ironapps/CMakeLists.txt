add_library(iron_apps STATIC
    app_socket.c
    echo_server.c
    dns_server.c
)
target_include_directories(iron_apps PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/common
    ${CMAKE_SOURCE_DIR}/ironstack
)
target_link_libraries(iron_apps iron_common)
