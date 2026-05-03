add_executable(test_stats unit/test_stats.c)
target_link_libraries(test_stats iron_common)

enable_testing()
add_test(NAME test_stats COMMAND test_stats)
