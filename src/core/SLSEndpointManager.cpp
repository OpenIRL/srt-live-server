#include "SLSEndpointManager.hpp"
#include <fstream>
#include <random>
#include <chrono>
#include <jwt-cpp/jwt.h>
#include <nlohmann/json.hpp>
#include "spdlog/spdlog.h"
#include "common.hpp"

using json = nlohmann::json;

CSLSEndpointManager::CSLSEndpointManager() {
    // Entferne das automatische Generieren und Speichern hier
    // Es wird erst nach set_config_file und set_auth_config gemacht
}

CSLSEndpointManager::~CSLSEndpointManager() {
    save_endpoints();
}

void CSLSEndpointManager::set_auth_config(const SLSEndpointAuth& auth) {
    CSLSLock lock(&m_mutex);
    m_auth.username = std::string(auth.username);
    m_auth.password = std::string(auth.password);
    m_auth.token_secret = std::string(auth.token_secret);
    m_auth.token_expire = auth.token_expire;
}

std::string CSLSEndpointManager::authenticate(const std::string& username, const std::string& password) {
    if (username != m_auth.username || password != m_auth.password) {
        return "";
    }

    auto token = jwt::create()
        .set_issuer("srt-server")
        .set_type("JWS")
        .set_issued_at(std::chrono::system_clock::now())
        .set_expires_at(std::chrono::system_clock::now() + std::chrono::seconds(m_auth.token_expire))
        .set_payload_claim("username", jwt::claim(username))
        .sign(jwt::algorithm::hs256{m_auth.token_secret});

    return token;
}

bool CSLSEndpointManager::verify_token(const std::string& token) {
    try {
        auto decoded = jwt::decode(token);
        auto verifier = jwt::verify()
            .allow_algorithm(jwt::algorithm::hs256{m_auth.token_secret})
            .with_issuer("srt-server");
            
        verifier.verify(decoded);
        return true;
    } catch (std::exception& e) {
        spdlog::error("Token verification failed: {}", e.what());
        return false;
    }
}

bool CSLSEndpointManager::verify_auth_header(const std::string& auth_header) {
    try {
        if (auth_header.substr(0, 7) != "Bearer ") {
            return false;
        }
        return verify_token(auth_header.substr(7));
    } catch (std::exception& e) {
        spdlog::error("Auth header verification failed: {}", e.what());
        return false;
    }
}

int CSLSEndpointManager::load_endpoints() {
    CSLSLock lock(&m_mutex);
    try {
        std::ifstream file(m_config_file);
        if (!file.is_open()) {
            spdlog::warn("Could not open endpoint config file, using empty configuration");
            return SLS_OK;
        }

        json j;
        file >> j;
        m_endpoints.clear();
        
        for (const auto& endpoint : j["endpoints"]) {
            SLSEndpoint e;
            e.ingest = endpoint["ingest"].get<std::string>();
            e.outgest = endpoint["outgest"].get<std::string>();
            m_endpoints.push_back(e);
        }
        
        return SLS_OK;
    } catch (std::exception& e) {
        spdlog::error("Failed to load endpoints: {}", e.what());
        return SLS_ERROR;
    }
}

int CSLSEndpointManager::save_endpoints() {
    CSLSLock lock(&m_mutex);
    try {
        json j;
        j["endpoints"] = json::array();
        
        for (const auto& endpoint : m_endpoints) {
            j["endpoints"].push_back({
                {"ingest", endpoint.ingest},
                {"outgest", endpoint.outgest}
            });
        }

        std::ofstream file(m_config_file);
        if (!file.is_open()) {
            spdlog::error("Could not open endpoint config file for writing");
            return SLS_ERROR;
        }
        file << j.dump(4);
        return SLS_OK;
    } catch (std::exception& e) {
        spdlog::error("Failed to save endpoints: {}", e.what());
        return SLS_ERROR;
    }
}

SLSEndpoint CSLSEndpointManager::generate_endpoint_pair() {
    SLSEndpoint endpoint;
    endpoint.ingest = generate_random_string(8);
    endpoint.outgest = generate_random_string(8);
    return endpoint;
}

int CSLSEndpointManager::add_endpoint(const SLSEndpoint& endpoint) {
    CSLSLock lock(&m_mutex);
    
    // Check if ingest already exists
    if (is_valid_ingest(endpoint.ingest)) {
        return SLS_ERROR;
    }
    
    m_endpoints.push_back(endpoint);
    save_endpoints();
    return SLS_OK;
}

int CSLSEndpointManager::remove_endpoint(const std::string& ingest) {
    CSLSLock lock(&m_mutex);
    
    auto it = std::find_if(m_endpoints.begin(), m_endpoints.end(),
        [&ingest](const SLSEndpoint& e) { return e.ingest == ingest; });
        
    if (it == m_endpoints.end()) {
        return SLS_ERROR;
    }
    
    m_endpoints.erase(it);
    save_endpoints();
    return SLS_OK;
}

bool CSLSEndpointManager::is_valid_ingest(const std::string& ingest) {
    CSLSLock lock(&m_mutex);
    return std::any_of(m_endpoints.begin(), m_endpoints.end(),
        [&ingest](const SLSEndpoint& e) { return e.ingest == ingest; });
}

std::string CSLSEndpointManager::get_outgest(const std::string& ingest) {
    CSLSLock lock(&m_mutex);
    auto it = std::find_if(m_endpoints.begin(), m_endpoints.end(),
        [&ingest](const SLSEndpoint& e) { return e.ingest == ingest; });
        
    if (it == m_endpoints.end()) {
        return "";
    }
    
    return it->outgest;
}

std::string CSLSEndpointManager::generate_random_string(size_t length) {
    const std::string chars = 
        "0123456789"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz";
        
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, chars.size() - 1);
    
    std::string result;
    result.reserve(length);
    
    for (size_t i = 0; i < length; ++i) {
        result += chars[dis(gen)];
    }
    
    return result;
}

void CSLSEndpointManager::set_ports(const SLSEndpointPorts& ports) {
    m_ports = ports;
}

int CSLSEndpointManager::get_port_for_endpoint(const std::string& endpoint) {
    // Hauptlogik nur für ingest/outgest
    if (is_valid_ingest(endpoint)) {
        return m_ports.ingest_port;
    }
    return m_ports.outgest_port;
}

bool CSLSEndpointManager::is_valid_endpoint_for_port(const std::string& endpoint, int port) {
    if (port == m_ports.ingest_port) {
        return is_valid_ingest(endpoint);
    }
    if (port == m_ports.outgest_port) {
        return !is_valid_ingest(endpoint);  // Outgest ist alles, was kein Ingest ist
    }
    return port == m_ports.http_port;  // Erlaubt HTTP-Port für Stats
}

bool CSLSEndpointManager::is_valid_ingest(const std::string& endpoint) {
    return endpoint.find("/ingest/") != std::string::npos;
} 