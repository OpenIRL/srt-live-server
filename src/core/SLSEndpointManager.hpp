#pragma once

#include <string>
#include <vector>
#include <algorithm>
#include "SLSLock.hpp"
#include "common.hpp"

struct SLSEndpointAuth {
    std::string username;
    std::string password;
    std::string token_secret;
    int token_expire;
};

struct SLSEndpoint {
    std::string ingest;
    std::string outgest;
};

struct SLSEndpointPorts {
    int ingest_port;
    int outgest_port;
    int http_port;
};

class CSLSEndpointManager {
public:
    CSLSEndpointManager();
    ~CSLSEndpointManager();

    void set_auth_config(const SLSEndpointAuth& auth);
    std::string authenticate(const std::string& username, const std::string& password);
    bool verify_token(const std::string& token);
    
    int load_endpoints();
    int save_endpoints();
    SLSEndpoint generate_endpoint_pair();
    int add_endpoint(const SLSEndpoint& endpoint);
    int remove_endpoint(const std::string& ingest);
    bool is_valid_ingest(const std::string& ingest);
    std::string get_outgest(const std::string& ingest);
    
    bool is_valid_outgest(const std::string& outgest) {
        CSLSLock lock(&m_mutex);
        return std::any_of(m_endpoints.begin(), m_endpoints.end(),
            [&outgest](const SLSEndpoint& e) { return e.outgest == outgest; });
    }

    const std::vector<SLSEndpoint>& get_all_endpoints() const {
        return m_endpoints;
    }

    void set_config_file(const std::string& config_file) {
        m_config_file = config_file;
    }

    bool is_valid_endpoint_for_port(const std::string& streamid, int port) {
        CSLSLock lock(&m_mutex);
        if (port == m_ports.ingest_port) {
            return is_valid_ingest(streamid);
        } else if (port == m_ports.outgest_port) {
            return is_valid_outgest(streamid);
        }
        return false;
    }

    void set_ports(const SLSEndpointPorts& ports);
    int get_port_for_endpoint(const std::string& endpoint);
    bool is_valid_endpoint_for_port(const std::string& endpoint, int port);
    bool is_valid_ingest(const std::string& endpoint);

private:
    std::vector<SLSEndpoint> m_endpoints;
    std::string m_config_file;
    CSLSMutex m_mutex;
    SLSEndpointAuth m_auth;
    SLSEndpointPorts m_ports;
    
    std::string generate_random_string(size_t length);
    bool verify_auth_header(const std::string& auth_header);
}; 