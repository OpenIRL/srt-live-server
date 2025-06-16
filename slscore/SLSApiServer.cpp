/**
 * The MIT License (MIT)
 *
 * Copyright (c) 2025 OpenIRL
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 * the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 * IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#include "SLSApiServer.hpp"
#include "SLSDatabase.hpp"
#include "SLSManager.hpp"
#include "SLSLog.hpp"
#include "version.hpp"
#include <cstring>

CSLSApiServer::CSLSApiServer() : m_port(8080), m_sls_manager(nullptr), m_conf(nullptr) {
}

CSLSApiServer::~CSLSApiServer() {
    stop();
}

bool CSLSApiServer::init(sls_conf_srt_t* conf, CSLSManager* manager) {
    if (!conf || !manager) {
        return false;
    }
    
    m_conf = conf;
    m_sls_manager = manager;
    m_port = conf->http_port > 0 ? conf->http_port : 8080;
    
    // Initialize rate limits from configuration with defaults
    m_rate_limit_config["api"] = conf->rate_limit_api > 0 ? conf->rate_limit_api : 30;
    m_rate_limit_config["stats"] = conf->rate_limit_stats > 0 ? conf->rate_limit_stats : 300;
    m_rate_limit_config["config"] = conf->rate_limit_config > 0 ? conf->rate_limit_config : 20;
    
    sls_log(SLS_LOG_INFO, "[CSLSApiServer] Rate limits configured: api=%d/min, stats=%d/min, config=%d/min",
            m_rate_limit_config["api"], m_rate_limit_config["stats"], m_rate_limit_config["config"]);
    
    setupEndpoints();
    return true;
}

void CSLSApiServer::start() {
    m_server_thread = std::thread([this]() {
        sls_log(SLS_LOG_INFO, "[CSLSApiServer] HTTP API server listening on port %d", m_port);
        sls_log(SLS_LOG_INFO, "[CSLSApiServer] API requires authentication. Use Authorization: Bearer <API_KEY> header.");
        m_server.listen("0.0.0.0", m_port);
    });
}

void CSLSApiServer::stop() {
    sls_log(SLS_LOG_INFO, "[CSLSApiServer] Stopping API server...");
    m_server.stop();
    if (m_server_thread.joinable()) {
        m_server_thread.join();
    }
}

void CSLSApiServer::setCorsHeaders(httplib::Response& res) {
    res.set_header("Access-Control-Allow-Origin", "*");
    res.set_header("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS");
    res.set_header("Access-Control-Allow-Headers", "Content-Type, Authorization");
}

bool CSLSApiServer::checkRateLimit(const std::string& ip, const std::string& endpoint_type) {
    std::lock_guard<std::mutex> lock(m_rate_limit_mutex);
    
    // Get the configured limit for this endpoint type
    auto limit_it = m_rate_limit_config.find(endpoint_type);
    if (limit_it == m_rate_limit_config.end()) {
        // Unknown endpoint type, allow by default
        return true;
    }
    int max_requests = limit_it->second;
    
    // Create a unique key for each IP + endpoint type combination
    // This ensures that different endpoint types have separate rate limit counters
    std::string rate_limit_key = ip + ":" + endpoint_type;
    
    auto now = std::chrono::steady_clock::now();
    auto& limit_info = m_rate_limits[rate_limit_key];
    
    // Check if we need to reset the window (always 60 seconds)
    auto window_duration = std::chrono::duration_cast<std::chrono::seconds>(now - limit_info.window_start).count();
    if (window_duration >= 60) {
        limit_info.requests = 0;
        limit_info.window_start = now;
    }
    
    // Check if limit exceeded
    if (limit_info.requests >= max_requests) {
        return false;
    }
    
    limit_info.requests++;
    return true;
}

bool CSLSApiServer::authenticateRequest(const httplib::Request& req, httplib::Response& res, std::string& permissions) {
    // Check for API key in Authorization header
    auto auth_header = req.get_header_value("Authorization");
    if (auth_header.empty() || auth_header.substr(0, 7) != "Bearer ") {
        res.status = 401;
        json error;
        error["status"] = "error";
        error["message"] = "Missing or invalid Authorization header";
        res.set_content(error.dump(), "application/json");
        return false;
    }
    
    std::string api_key = auth_header.substr(7);
    bool valid = CSLSDatabase::getInstance().verifyApiKey(api_key, permissions);
    
    if (!valid) {
        res.status = 401;
        json error;
        error["status"] = "error";
        error["message"] = "Invalid API key";
        res.set_content(error.dump(), "application/json");
        
        // Log failed attempt
        CSLSDatabase::getInstance().logAccess(api_key, req.path, req.method, req.remote_addr, 401);
        return false;
    }
    
    return true;
}

void CSLSApiServer::setupEndpoints() {
    // Health check endpoint (no auth required)
    m_server.Get("/health", [this](const httplib::Request& req, httplib::Response& res) {
        handleHealth(req, res);
    });
    
    // Handle CORS preflight
    m_server.Options(".*", [](const httplib::Request& req, httplib::Response& res) {
        setCorsHeaders(res);
        res.status = 204;
    });
    
    // Stream IDs API endpoints
    m_server.Get("/api/stream-ids", [this](const httplib::Request& req, httplib::Response& res) {
        handleStreamIdsGet(req, res);
    });
    
    m_server.Post("/api/stream-ids", [this](const httplib::Request& req, httplib::Response& res) {
        handleStreamIdsPost(req, res);
    });
    
    m_server.Delete(R"(/api/stream-ids/([^/]+))", [this](const httplib::Request& req, httplib::Response& res) {
        handleStreamIdsDelete(req, res);
    });
    
    // Statistics endpoint
    m_server.Get(R"(/stats/(.+))", [this](const httplib::Request& req, httplib::Response& res) {
        handleStats(req, res);
    });
    
    // Configuration endpoint
    m_server.Get("/api/config", [this](const httplib::Request& req, httplib::Response& res) {
        handleConfig(req, res);
    });
    
    // API key management endpoint
    m_server.Post("/api/keys", [this](const httplib::Request& req, httplib::Response& res) {
        handleApiKeys(req, res);
    });
}

void CSLSApiServer::handleHealth(const httplib::Request& req, httplib::Response& res) {
    setCorsHeaders(res);
    
    json response;
    response["status"] = "ok";
    response["service"] = "srt-live-server";
    response["version"] = std::string(SLS_MAJOR_VERSION) + "." + SLS_MIN_VERSION + "." + SLS_TEST_VERSION;
    res.set_content(response.dump(), "application/json");
}

void CSLSApiServer::handleStreamIdsGet(const httplib::Request& req, httplib::Response& res) {
    setCorsHeaders(res);
    
    // Rate limiting
    if (!checkRateLimit(req.remote_addr, "api")) {
        res.status = 429;
        json error;
        error["status"] = "error";
        error["message"] = "Rate limit exceeded";
        res.set_content(error.dump(), "application/json");
        return;
    }
    
    // Authentication
    std::string permissions;
    if (!authenticateRequest(req, res, permissions)) {
        return;
    }
    
    // Get stream IDs
    json response;
    response["status"] = "success";
    response["data"] = CSLSDatabase::getInstance().getStreamIds();
    
    res.set_content(response.dump(), "application/json");
    CSLSDatabase::getInstance().logAccess(req.get_header_value("Authorization").substr(7), 
                         req.path, req.method, req.remote_addr, 200);
}

void CSLSApiServer::handleStreamIdsPost(const httplib::Request& req, httplib::Response& res) {
    setCorsHeaders(res);
    
    // Rate limiting
    if (!checkRateLimit(req.remote_addr, "api")) {
        res.status = 429;
        json error;
        error["status"] = "error";
        error["message"] = "Rate limit exceeded";
        res.set_content(error.dump(), "application/json");
        return;
    }
    
    // Authentication with admin check
    std::string permissions;
    if (!authenticateRequest(req, res, permissions)) {
        return;
    }
    
    if (permissions != "admin" && permissions != "write") {
        res.status = 403;
        json error;
        error["status"] = "error";
        error["message"] = "Insufficient permissions";
        res.set_content(error.dump(), "application/json");
        CSLSDatabase::getInstance().logAccess(req.get_header_value("Authorization").substr(7), 
                             req.path, req.method, req.remote_addr, 403);
        return;
    }
    
    // Parse request body
    json body;
    try {
        body = json::parse(req.body);
    } catch (const std::exception& e) {
        res.status = 400;
        json error;
        error["status"] = "error";
        error["message"] = "Invalid JSON body";
        res.set_content(error.dump(), "application/json");
        return;
    }
    
    // Validate required fields
    if (!body.contains("publisher") || !body.contains("player") ||
        !body["publisher"].is_string() || !body["player"].is_string()) {
        res.status = 400;
        json error;
        error["status"] = "error";
        error["message"] = "Missing or invalid required fields: publisher, player";
        res.set_content(error.dump(), "application/json");
        return;
    }
    
    std::string publisher = body["publisher"];
    std::string player = body["player"];
    std::string description = body.value("description", "");
    
    // Add to database
    if (CSLSDatabase::getInstance().addStreamId(publisher, player, description)) {
        json response;
        response["status"] = "success";
        response["message"] = "Stream ID added successfully";
        res.set_content(response.dump(), "application/json");
        
        CSLSDatabase::getInstance().logAccess(req.get_header_value("Authorization").substr(7), 
                             req.path, req.method, req.remote_addr, 200);
    } else {
        res.status = 409; // Conflict
        json error;
        error["status"] = "error";
        error["message"] = "Stream ID with player '" + player + "' already exists";
        res.set_content(error.dump(), "application/json");
        
        CSLSDatabase::getInstance().logAccess(req.get_header_value("Authorization").substr(7), 
                             req.path, req.method, req.remote_addr, 409);
    }
}

void CSLSApiServer::handleStreamIdsDelete(const httplib::Request& req, httplib::Response& res) {
    setCorsHeaders(res);
    
    // Rate limiting
    if (!checkRateLimit(req.remote_addr, "api")) {
        res.status = 429;
        json error;
        error["status"] = "error";
        error["message"] = "Rate limit exceeded";
        res.set_content(error.dump(), "application/json");
        return;
    }
    
    // Authentication with admin check
    std::string permissions;
    if (!authenticateRequest(req, res, permissions)) {
        return;
    }
    
    if (permissions != "admin") {
        res.status = 403;
        json error;
        error["status"] = "error";
        error["message"] = "Admin permissions required";
        res.set_content(error.dump(), "application/json");
        CSLSDatabase::getInstance().logAccess(req.get_header_value("Authorization").substr(7), 
                             req.path, req.method, req.remote_addr, 403);
        return;
    }
    
    std::string player_id = req.matches[1];
    
    if (CSLSDatabase::getInstance().deleteStreamId(player_id)) {
        json response;
        response["status"] = "success";
        response["message"] = "Stream ID deleted successfully";
        res.set_content(response.dump(), "application/json");
        
        CSLSDatabase::getInstance().logAccess(req.get_header_value("Authorization").substr(7), 
                             req.path, req.method, req.remote_addr, 200);
    } else {
        res.status = 404;
        json error;
        error["status"] = "error";
        error["message"] = "Stream ID not found";
        res.set_content(error.dump(), "application/json");
    }
}

void CSLSApiServer::handleStats(const httplib::Request& req, httplib::Response& res) {
    setCorsHeaders(res);
    
    // Rate limiting (but no authentication required for stats)
    if (!checkRateLimit(req.remote_addr, "stats")) {
        res.status = 429;
        json error;
        error["status"] = "error";
        error["message"] = "Rate limit exceeded";
        res.set_content(error.dump(), "application/json");
        return;
    }
    
    json ret;

    if (!m_sls_manager) {
        ret["status"] = "error";
        ret["message"] = "sls manager not found";
        res.status = 500;
        res.set_content(ret.dump(), "application/json");
        return;
    }

    ret = m_sls_manager->generate_json_for_publisher(req.matches[1], req.has_param("reset") ? 1 : 0);
    if (ret["status"] == "error") {
        res.status = 404;
    }

    res.set_content(ret.dump(), "application/json");
}

void CSLSApiServer::handleConfig(const httplib::Request& req, httplib::Response& res) {
    setCorsHeaders(res);
    
    // Rate limiting
    if (!checkRateLimit(req.remote_addr, "config")) {
        res.status = 429;
        json error;
        error["status"] = "error";
        error["message"] = "Rate limit exceeded";
        res.set_content(error.dump(), "application/json");
        return;
    }
    
    // Authentication
    std::string permissions;
    if (!authenticateRequest(req, res, permissions)) {
        return;
    }
    
    json response;
    response["status"] = "success";
    json config;
    
    // Get configuration from conf structure
    config["listen_publisher"] = 4001;  // These are hardcoded as defaults in server conf
    config["listen_player"] = 4000;
    config["http_port"] = m_conf ? m_conf->http_port : 8080;
    
    config["latency_min"] = 200; // default minimum latency
    config["latency_max"] = 5000; // default maximum latency
    
    response["data"] = config;
    
    res.set_content(response.dump(), "application/json");
    CSLSDatabase::getInstance().logAccess(req.get_header_value("Authorization").substr(7), 
                         req.path, req.method, req.remote_addr, 200);
}

void CSLSApiServer::handleApiKeys(const httplib::Request& req, httplib::Response& res) {
    setCorsHeaders(res);
    
    // Rate limiting
    if (!checkRateLimit(req.remote_addr, "config")) {
        res.status = 429;
        json error;
        error["status"] = "error";
        error["message"] = "Rate limit exceeded";
        res.set_content(error.dump(), "application/json");
        return;
    }
    
    // Authentication with admin check
    std::string permissions;
    if (!authenticateRequest(req, res, permissions)) {
        return;
    }
    
    if (permissions != "admin") {
        res.status = 403;
        json error;
        error["status"] = "error";
        error["message"] = "Admin permissions required";
        res.set_content(error.dump(), "application/json");
        return;
    }
    
    // Parse request body
    json body;
    try {
        body = json::parse(req.body);
    } catch (const std::exception& e) {
        res.status = 400;
        json error;
        error["status"] = "error";
        error["message"] = "Invalid JSON body";
        res.set_content(error.dump(), "application/json");
        return;
    }
    
    std::string name = body.value("name", "New API Key");
    std::string key_permissions = body.value("permissions", "read");
    
    // Generate new API key
    std::string new_key;
    if (CSLSDatabase::getInstance().createApiKey(name, key_permissions, new_key)) {
        json response;
        response["status"] = "success";
        response["api_key"] = new_key;
        response["message"] = "Save this key securely. It cannot be retrieved again.";
        res.set_content(response.dump(), "application/json");
    } else {
        res.status = 500;
        json error;
        error["status"] = "error";
        error["message"] = "Failed to create API key";
        res.set_content(error.dump(), "application/json");
    }
} 