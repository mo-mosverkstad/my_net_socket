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

enable_testing()

# Unit tests
add_test(NAME test_stats COMMAND test_stats)
add_test(NAME test_eth COMMAND test_eth)
add_test(NAME test_route COMMAND test_route)
add_test(NAME test_acl COMMAND test_acl)
add_test(NAME test_tcp COMMAND test_tcp)

# Module tests
add_test(NAME module_l2 COMMAND test_l2_module)
add_test(NAME module_l3 COMMAND test_l3_module)
add_test(NAME module_pbr_acl COMMAND test_pbr_acl_module)
add_test(NAME module_l4 COMMAND test_l4_module)
