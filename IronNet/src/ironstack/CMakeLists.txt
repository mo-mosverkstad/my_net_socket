add_executable(ironstack
    main.c
    core/pipeline.c
    core/config.c
    io/vnic.c
    l2/eth.c
)

target_include_directories(ironstack PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/common
)

target_link_libraries(ironstack iron_common)
