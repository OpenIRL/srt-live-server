cmake_minimum_required(VERSION 3.0.0)
project(srt-live-server VERSION 2.1.0)

set(CMAKE_CXX_STANDARD 17)

set(CMAKE_CXX_FLAGS "-Wall -Wno-invalid-offsetof -fcompare-debug-second")
set(CMAKE_CXX_FLAGS_DEBUG "-g")
set(CMAKE_CXX_FLAGS_RELEASE "-O3 -s")

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# OpenSSL
find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})

# jwt-cpp (header-only library)
add_subdirectory(lib/jwt-cpp EXCLUDE_FROM_ALL)
include_directories(${CMAKE_SOURCE_DIR}/lib/jwt-cpp/include)

# Rest of existing configuration...
add_subdirectory(${PROJECT_SOURCE_DIR}/lib/spdlog)
find_package(spdlog)

set(JSON_BuildTests OFF CACHE INTERNAL "")
add_subdirectory(${PROJECT_SOURCE_DIR}/lib/json)

find_package(Threads)
add_subdirectory(${PROJECT_SOURCE_DIR}/src)

target_link_libraries(srt_server 
    PRIVATE 
    spdlog::spdlog
    nlohmann_json::nlohmann_json
    ${OPENSSL_LIBRARIES}
    OpenSSL::SSL
    OpenSSL::Crypto
)
