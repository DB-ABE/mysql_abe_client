project(test)

set(BUILD_GMOCK ON)
set(INSTALL_GTEST OFF)

add_subdirectory(${PROJECT_ROOT}/googletest-1.14.0 googletest)

add_executable(test_crypto abe_crypto_unittest.cpp)

target_include_directories(test_crypto PUBLIC ${PROJECT_ROOT}/googletest-1.14.0/include)
target_include_directories(test_crypto PUBLIC ${PROJECT_ROOT})
target_link_libraries(test_crypto PUBLIC src gtest gtest_main gmock mysqlpp mysqlclient crypto relic relic_ec openabe)

add_test(NAME test_crypto COMMAND test_crypto)

install(DIRECTORY  ${CMAKE_CURRENT_SOURCE_DIR}/data 
        DESTINATION ${CMAKE_BINARY_DIR})