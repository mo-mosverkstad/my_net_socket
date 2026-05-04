add_executable(ironstack
    main.c
    core/pipeline.c
    core/config.c
    core/iface.c
    core/router_conf.c
    io/vnic.c
    l2/eth.c
    l2/arp.c
    l2/vlan.c
    l2/bridge.c
    l3/ip.c
    l3/route.c
    l3/route_table.c
    l3/icmp.c
    l3/acl.c
    l3/pbr.c
    l3/conntrack.c
    l3/ip_frag.c
    l4/udp.c
    l4/tcp.c
    security/ipsec.c
)

target_include_directories(ironstack PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/common
)

target_link_libraries(ironstack iron_common)
