# Server module
add_library(server
    server.cpp
    router.cpp
    request.cpp
    response.cpp
    config_loader.cpp
    file_handler.cpp
    logger.cpp
    threadpool.cpp
    JwtHandler.cpp
    SecurityManager.cpp
    TLSContext.cpp
)

target_include_directories(server PUBLIC ${CMAKE_SOURCE_DIR}/include/server ${CMAKE_SOURCE_DIR}/include)
target_link_libraries(server PUBLIC OpenSSL::SSL OpenSSL::Crypto Threads::Threads)

if(WIN32)
    target_link_libraries(server PUBLIC ws2_32)
elseif(UNIX)
    target_link_libraries(server PUBLIC ${CMAKE_DL_LIBS})
endif()
