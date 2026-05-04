# Unit tests
add_executable(test_stats unit/test_stats.c)
target_link_libraries(test_stats iron_common)

add_executable(test_eth unit/test_eth.c)
target_include_directories(test_eth PRIVATE
    ${CMAKE_SOURCE_DIR}/common
    ${CMAKE_SOURCE_DIR}/ironstack
)
target_link_libraries(test_eth iron_common)

add_executable(test_route unit/test_route.c)
target_include_directories(test_route PRIVATE
    ${CMAKE_SOURCE_DIR}/common
    ${CMAKE_SOURCE_DIR}/ironstack
)
target_link_libraries(test_route iron_common)

add_executable(test_acl unit/test_acl.c)
target_include_directories(test_acl PRIVATE
    ${CMAKE_SOURCE_DIR}/common
    ${CMAKE_SOURCE_DIR}/ironstack
)
target_link_libraries(test_acl iron_common)

add_executable(test_tcp unit/test_tcp.c)
target_include_directories(test_tcp PRIVATE
    ${CMAKE_SOURCE_DIR}/common
    ${CMAKE_SOURCE_DIR}/ironstack
)
target_link_libraries(test_tcp iron_common)

add_executable(test_ipsec unit/test_ipsec.c)
target_include_directories(test_ipsec PRIVATE
    ${CMAKE_SOURCE_DIR}/common
    ${CMAKE_SOURCE_DIR}/ironstack
)
target_link_libraries(test_ipsec iron_common)

add_executable(test_vlan unit/test_vlan.c)
target_include_directories(test_vlan PRIVATE
    ${CMAKE_SOURCE_DIR}/common
    ${CMAKE_SOURCE_DIR}/ironstack
)
target_link_libraries(test_vlan iron_common)

add_executable(test_arp unit/test_arp.c)
target_include_directories(test_arp PRIVATE
    ${CMAKE_SOURCE_DIR}/common
    ${CMAKE_SOURCE_DIR}/ironstack
)
target_link_libraries(test_arp iron_common)

add_executable(test_ip_frag unit/test_ip_frag.c)
target_include_directories(test_ip_frag PRIVATE
    ${CMAKE_SOURCE_DIR}/common
    ${CMAKE_SOURCE_DIR}/ironstack
)
target_link_libraries(test_ip_frag iron_common)

add_executable(test_iface unit/test_iface.c)
target_include_directories(test_iface PRIVATE
    ${CMAKE_SOURCE_DIR}/common
    ${CMAKE_SOURCE_DIR}/ironstack
)
target_link_libraries(test_iface iron_common)

add_executable(test_pbr unit/test_pbr.c)
target_include_directories(test_pbr PRIVATE
    ${CMAKE_SOURCE_DIR}/common
    ${CMAKE_SOURCE_DIR}/ironstack
)
target_link_libraries(test_pbr iron_common)

add_executable(test_route_table unit/test_route_table.c)
target_include_directories(test_route_table PRIVATE
    ${CMAKE_SOURCE_DIR}/common
    ${CMAKE_SOURCE_DIR}/ironstack
)
target_link_libraries(test_route_table iron_common)

add_executable(test_conntrack unit/test_conntrack.c)
target_include_directories(test_conntrack PRIVATE
    ${CMAKE_SOURCE_DIR}/common
    ${CMAKE_SOURCE_DIR}/ironstack
)
target_link_libraries(test_conntrack iron_common)

# Module tests
add_executable(test_l2_module module/test_l2_module.c)
target_include_directories(test_l2_module PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/module
    ${CMAKE_SOURCE_DIR}/common
    ${CMAKE_SOURCE_DIR}/ironstack
)
target_link_libraries(test_l2_module iron_common)

add_executable(test_l3_module module/test_l3_module.c)
target_include_directories(test_l3_module PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/module
    ${CMAKE_SOURCE_DIR}/common
    ${CMAKE_SOURCE_DIR}/ironstack
)
target_link_libraries(test_l3_module iron_common)

add_executable(test_pbr_acl_module module/test_pbr_acl_module.c)
target_include_directories(test_pbr_acl_module PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/module
    ${CMAKE_SOURCE_DIR}/common
    ${CMAKE_SOURCE_DIR}/ironstack
)
target_link_libraries(test_pbr_acl_module iron_common)

add_executable(test_l4_module module/test_l4_module.c)
target_include_directories(test_l4_module PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/module
    ${CMAKE_SOURCE_DIR}/common
    ${CMAKE_SOURCE_DIR}/ironstack
)
target_link_libraries(test_l4_module iron_common)

add_executable(test_ipsec_module module/test_ipsec_module.c)
target_include_directories(test_ipsec_module PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/module
    ${CMAKE_SOURCE_DIR}/common
    ${CMAKE_SOURCE_DIR}/ironstack
)
target_link_libraries(test_ipsec_module iron_common)

add_executable(test_vlan_module module/test_vlan_module.c)
target_include_directories(test_vlan_module PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/module
    ${CMAKE_SOURCE_DIR}/common
    ${CMAKE_SOURCE_DIR}/ironstack
)
target_link_libraries(test_vlan_module iron_common)

add_executable(test_bridge_module module/test_bridge_module.c)
target_include_directories(test_bridge_module PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/module
    ${CMAKE_SOURCE_DIR}/common
    ${CMAKE_SOURCE_DIR}/ironstack
)
target_link_libraries(test_bridge_module iron_common)

add_executable(test_route_table_module module/test_route_table_module.c)
target_include_directories(test_route_table_module PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/module
    ${CMAKE_SOURCE_DIR}/common
    ${CMAKE_SOURCE_DIR}/ironstack
)
target_link_libraries(test_route_table_module iron_common)

add_executable(test_conntrack_module module/test_conntrack_module.c)
target_include_directories(test_conntrack_module PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/module
    ${CMAKE_SOURCE_DIR}/common
    ${CMAKE_SOURCE_DIR}/ironstack
)
target_link_libraries(test_conntrack_module iron_common)

enable_testing()

# Unit tests
add_test(NAME test_stats COMMAND test_stats)
add_test(NAME test_eth COMMAND test_eth)
add_test(NAME test_route COMMAND test_route)
add_test(NAME test_acl COMMAND test_acl)
add_test(NAME test_tcp COMMAND test_tcp)
add_test(NAME test_ipsec COMMAND test_ipsec)
add_test(NAME test_vlan COMMAND test_vlan)
add_test(NAME test_arp COMMAND test_arp)
add_test(NAME test_ip_frag COMMAND test_ip_frag)
add_test(NAME test_iface COMMAND test_iface)
add_test(NAME test_pbr COMMAND test_pbr)
add_test(NAME test_route_table COMMAND test_route_table)
add_test(NAME test_conntrack COMMAND test_conntrack)

# Module tests
add_test(NAME module_l2 COMMAND test_l2_module)
add_test(NAME module_l3 COMMAND test_l3_module)
add_test(NAME module_pbr_acl COMMAND test_pbr_acl_module)
add_test(NAME module_l4 COMMAND test_l4_module)
add_test(NAME module_ipsec COMMAND test_ipsec_module)
add_test(NAME module_vlan COMMAND test_vlan_module)
add_test(NAME module_bridge COMMAND test_bridge_module)
add_test(NAME module_route_table COMMAND test_route_table_module)
add_test(NAME module_conntrack COMMAND test_conntrack_module)
