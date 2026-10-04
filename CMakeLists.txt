cmake_minimum_required(VERSION 3.15)
project(InfraLite-Secure-Cloud-Gateway LANGUAGES C CXX)

include(CTest)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

if(MSVC)
    add_compile_options(/Zc:__cplusplus /utf-8 /permissive- /W3)
endif()

if(WIN32)
    add_compile_definitions(NOMINMAX WIN32_LEAN_AND_MEAN)
endif()

# Backend headers shared by the server and repository modules.
include_directories(include)

add_subdirectory(src/server)
add_subdirectory(src/db)

if(BUILD_TESTING)
    include(FetchContent)
    set(INSTALL_GTEST OFF CACHE BOOL "Disable GoogleTest installation" FORCE)
    set(gtest_force_shared_crt ON CACHE BOOL "Use the shared MSVC runtime" FORCE)
    FetchContent_Declare(
        googletest
        GIT_REPOSITORY https://github.com/google/googletest.git
        GIT_TAG v1.15.2
        GIT_SHALLOW TRUE
    )
    FetchContent_MakeAvailable(googletest)

    add_executable(infralite-tests tests/backend_tests.cpp)
    target_link_libraries(infralite-tests PRIVATE server db GTest::gtest_main)
    include(GoogleTest)
    gtest_discover_tests(infralite-tests)
endif()

add_executable(infralite-server
    src/server/server_main.cpp
)

target_include_directories(infralite-server PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/include/server
)

target_link_libraries(infralite-server PRIVATE server db)

if(WIN32 AND EXISTS "${OPENSSL_INCLUDE_DIR}/openssl/applink.c")
    target_sources(infralite-server PRIVATE "${OPENSSL_INCLUDE_DIR}/openssl/applink.c")
endif()

