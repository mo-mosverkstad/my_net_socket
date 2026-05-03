# Unit tests
add_executable(test_stats unit/test_stats.c)
target_link_libraries(test_stats iron_common)

add_executable(test_eth unit/test_eth.c)
target_include_directories(test_eth PRIVATE
    ${CMAKE_SOURCE_DIR}/common
    ${CMAKE_SOURCE_DIR}/ironstack
)
target_link_libraries(test_eth iron_common)

# Module tests
add_executable(test_l2_module module/test_l2_module.c)
target_include_directories(test_l2_module PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/module
    ${CMAKE_SOURCE_DIR}/common
    ${CMAKE_SOURCE_DIR}/ironstack
)
target_link_libraries(test_l2_module iron_common)

enable_testing()

# Unit tests
add_test(NAME test_stats COMMAND test_stats)
add_test(NAME test_eth COMMAND test_eth)

# Module tests
add_test(NAME module_l2 COMMAND test_l2_module)
