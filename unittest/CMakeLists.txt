project(test)

set(BUILD_GMOCK ON)
set(INSTALL_GTEST OFF)

add_subdirectory(${PROJECT_ROOT}/googletest-1.14.0 googletest)


add_executable(test_crypto abe_crypto_unittest.cpp)

set_target_properties(test_crypto
    PROPERTIES
    COMPILE_FLAGS "-fprofile-arcs -ftest-coverage"
    LINK_FLAGS " -lgcov --coverage"
)
target_include_directories(test_crypto PUBLIC ${PROJECT_ROOT}/googletest-1.14.0/include)
target_include_directories(test_crypto PUBLIC ${PROJECT_ROOT})
target_link_libraries(test_crypto PUBLIC src gtest gtest_main gmock mysqlpp mysqlclient crypto relic relic_ec openabe)
target_link_libraries(test_crypto PRIVATE gcov)


add_executable(test_parameters parameters_unittest.cpp)
set_target_properties(test_parameters
    PROPERTIES
    COMPILE_FLAGS "-fprofile-arcs -ftest-coverage"
    LINK_FLAGS " -lgcov --coverage"
)
target_include_directories(test_parameters PUBLIC ${PROJECT_ROOT}/googletest-1.14.0/include)
target_include_directories(test_parameters PUBLIC ${PROJECT_ROOT})
target_link_libraries(test_parameters PUBLIC src gtest gtest_main gmock mysqlpp mysqlclient crypto relic relic_ec openabe)
target_link_libraries(test_parameters PRIVATE gcov)


add_executable(test_rewrite rewrite_unittest.cpp)
set_target_properties(test_rewrite
    PROPERTIES
    COMPILE_FLAGS "-fprofile-arcs -ftest-coverage"
    LINK_FLAGS " -lgcov --coverage"
)
target_include_directories(test_rewrite PUBLIC ${PROJECT_ROOT}/googletest-1.14.0/include)
target_include_directories(test_rewrite PUBLIC ${PROJECT_ROOT})
target_link_libraries(test_rewrite PUBLIC src gtest gtest_main gmock mysqlpp mysqlclient crypto relic relic_ec openabe)
target_link_libraries(test_rewrite PRIVATE gcov)




add_test(NAME test_crypto COMMAND test_crypto)
add_test(NAME test_parameters COMMAND test_parameters)
add_test(NAME test_rewrite COMMAND test_rewrite)


install(DIRECTORY  ${CMAKE_CURRENT_SOURCE_DIR}/data 
        DESTINATION ${CMAKE_BINARY_DIR})