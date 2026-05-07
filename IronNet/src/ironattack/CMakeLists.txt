add_executable(ironattack main.c craft.c dns_spoof_ext.c exploit.c covert.c mac_flood.c stealth_scan.c)
target_include_directories(ironattack PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(ironmitm mitm.c)
target_include_directories(ironmitm PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
