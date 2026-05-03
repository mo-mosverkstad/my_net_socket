add_executable(ironstack
    main.c
    core/pipeline.c
    core/config.c
    io/vnic.c
    l2/eth.c
    l3/ip.c
    l3/route.c
    l3/icmp.c
    l3/acl.c
    l3/pbr.c
    l4/udp.c
    l4/tcp.c
)

target_include_directories(ironstack PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/common
)

target_link_libraries(ironstack iron_common)
