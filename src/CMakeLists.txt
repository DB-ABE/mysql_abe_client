set(SOURCES
    abe_crypto.cpp
    parameters.cpp
    rewrite.cpp
    my_utils/base64.cpp 
    my_utils/config.cpp 
)
add_library(src STATIC ${SOURCES})
# target_link_libraries(src PUBLIC mysqlpp mysqlclient crypto relic relic_ec openabe)