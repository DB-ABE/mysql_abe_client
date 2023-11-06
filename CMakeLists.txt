cmake_minimum_required(VERSION 3.16)

project(abe_client VERSION 1.0 LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 11)
set(PROJECT_ROOT ${CMAKE_CURRENT_SOURCE_DIR})

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_CXX_FLAGS "-std=c++11 -g -Wall -Werror -DSSL_LIB_INIT")
option(RELEASE "debug mode" false)
if(NOT RELEASE)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g")
endif()
add_subdirectory(src)

include_directories(/usr/include/mysql /usr/local/include/mysql++)
link_directories(/usr/local/lib /usr/lib/x86_64-linux-gnu)

add_executable(abe_client main.cpp)
target_link_libraries(abe_client src mysqlpp mysqlclient crypto relic relic_ec openabe)

# 暂时安装在项目主目录
install(TARGETS  abe_client 
        RUNTIME DESTINATION  ${PROJECT_ROOT})

if(NOT RELEASE)
    enable_testing()
    add_subdirectory(unittest)
endif()