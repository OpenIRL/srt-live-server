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

#ifndef _SLS_DATABASE_HPP_
#define _SLS_DATABASE_HPP_

#include <string>
#include <vector>
#include <memory>
#include <mutex>
#include <sqlite3.h>
#include "json.hpp"
#include <chrono>
#include <unordered_map>
#include <shared_mutex>

using json = nlohmann::json;

/**
 * CSLSDatabase
 * Manages SQLite database for stream IDs and API keys
 */
class CSLSDatabase {
public:
    CSLSDatabase();
    ~CSLSDatabase();
    
    // Initialize database with path
    bool init(const std::string& db_path);
    void close();
    
    // Preload cache after initialization (optional)
    bool preloadCache();
    
    // Stream ID operations
    json getStreamIds();
    bool addStreamId(const std::string& publisher, const std::string& player, const std::string& description = "");
    bool deleteStreamId(const std::string& player);
    json getStreamIdMapping();
    bool validateStreamId(const char* stream_id, bool is_publisher, char* mapped_id = nullptr);

    // Authentication & API management
    bool verifyApiKey(const std::string& api_key, std::string& permissions);
    bool createApiKey(const std::string& name, const std::string& permissions, std::string& out_key);
    void logAccess(const std::string& api_key, const std::string& endpoint, 
                   const std::string& method, const std::string& ip, int response_code);

    // Get publisher from player ID with caching
    std::string getPublisherFromPlayer(const std::string& player_id);


    // Singleton pattern
    static CSLSDatabase& getInstance() {
        if (!m_instance) {
            m_instance = std::make_unique<CSLSDatabase>();
        }
        return *m_instance;
    }
    
private:
    sqlite3* m_db;
    std::mutex m_db_mutex;
    bool m_initialized;
    
    // In-memory cache for all stream IDs
    struct StreamIdEntry {
        std::string publisher;
        std::string player;
        std::string description;
    };
    
    // Complete in-memory cache of all stream IDs
    std::vector<StreamIdEntry> m_stream_ids_cache;
    std::unordered_map<std::string, std::string> m_player_to_publisher_cache; // Quick lookup
    mutable std::shared_mutex m_cache_mutex;  // Read-Write lock for better concurrency
    bool m_cache_loaded;
    
    // Initialize database schema
    bool initSchema();
    void insertDefaultApiKey();
    
    // Load all stream IDs into cache
    bool loadStreamIdsCacheIfNeeded() const;
    bool loadStreamIdsIntoCache();
    
    // API key management helpers
    std::string hashApiKey(const std::string& key);
    std::string generateApiKey();
    
    // Singleton
    static std::unique_ptr<CSLSDatabase> m_instance;
    static std::mutex m_instance_mutex;
};

#endif // _SLS_DATABASE_HPP_ 