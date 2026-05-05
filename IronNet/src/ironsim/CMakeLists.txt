add_executable(ironsim main.c)
target_include_directories(ironsim PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(ironsim-test test_traffic.c)
target_include_directories(ironsim-test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
