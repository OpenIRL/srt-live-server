add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/core)

add_executable(srt_server ${CMAKE_CURRENT_SOURCE_DIR}/srt-live-server.cpp)
target_link_libraries(srt_server
        sls_core
        spdlog
        -lsrt
        ${CMAKE_THREAD_LIBS_INIT}
        nlohmann_json::nlohmann_json
        ${OPENSSL_LIBRARIES}
        OpenSSL::SSL
        OpenSSL::Crypto
)

add_executable(srt_client ${CMAKE_CURRENT_SOURCE_DIR}/srt-live-client.cpp)
target_link_libraries(srt_client
        sls_core
        spdlog
        -lsrt
        ${CMAKE_THREAD_LIBS_INIT}
)

# Copy configuration file
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/sls.conf ${CMAKE_BINARY_DIR}/bin/sls.conf COPYONLY)
