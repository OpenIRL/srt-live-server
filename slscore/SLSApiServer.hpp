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

#ifndef _SLS_API_SERVER_HPP_
#define _SLS_API_SERVER_HPP_

#include <httplib.h>
#include <thread>
#include <unordered_map>
#include <mutex>
#include <chrono>
#include "json.hpp"
#include "SLSManager.hpp"

using json = nlohmann::json;

// Rate limiting structure
struct RateLimitInfo {
    int requests = 0;
    std::chrono::steady_clock::time_point window_start = std::chrono::steady_clock::now();
};

/**
 * CSLSApiServer
 * REST API server for SRT Live Server management
 */
class CSLSApiServer {
public:
    CSLSApiServer();
    ~CSLSApiServer();
    
    // Initialize and start API server
    bool init(sls_conf_srt_t* conf, CSLSManager* manager);
    void start();
    void stop();
    
    // Set CORS headers
    static void setCorsHeaders(httplib::Response& res);
    
private:
    httplib::Server m_server;
    std::thread m_server_thread;
    int m_port;
    CSLSManager* m_sls_manager;
    sls_conf_srt_t* m_conf;
    
    // Rate limiting
    std::unordered_map<std::string, RateLimitInfo> m_rate_limits;
    std::mutex m_rate_limit_mutex;
    
    // Helper functions
    bool checkRateLimit(const std::string& ip, int max_requests = 60, int window_seconds = 60);
    bool authenticateRequest(const httplib::Request& req, httplib::Response& res, std::string& permissions);
    
    // Setup all API endpoints
    void setupEndpoints();
    
    // Endpoint handlers
    void handleHealth(const httplib::Request& req, httplib::Response& res);
    void handleStreamIdsGet(const httplib::Request& req, httplib::Response& res);
    void handleStreamIdsPost(const httplib::Request& req, httplib::Response& res);
    void handleStreamIdsDelete(const httplib::Request& req, httplib::Response& res);
    void handleStats(const httplib::Request& req, httplib::Response& res);
    void handleConfig(const httplib::Request& req, httplib::Response& res);
    void handleApiKeys(const httplib::Request& req, httplib::Response& res);
};

#endif // _SLS_API_SERVER_HPP_ 