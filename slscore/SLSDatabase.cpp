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

#include "SLSDatabase.hpp"
#include "SLSLog.hpp"
#include <cstring>
#include <openssl/sha.h>
#include <random>
#include <sstream>
#include <iomanip>
#include <sys/stat.h>
#include <unistd.h>

// Singleton instance
std::unique_ptr<CSLSDatabase> CSLSDatabase::m_instance = nullptr;
std::mutex CSLSDatabase::m_instance_mutex;

CSLSDatabase::CSLSDatabase() : m_db(nullptr), m_initialized(false) {
}

CSLSDatabase::~CSLSDatabase() {
    close();
}

CSLSDatabase& CSLSDatabase::getInstance() {
    std::lock_guard<std::mutex> lock(m_instance_mutex);
    if (!m_instance) {
        m_instance.reset(new CSLSDatabase());
    }
    return *m_instance;
}

bool CSLSDatabase::init(const std::string& db_path) {
    std::lock_guard<std::mutex> lock(m_db_mutex);
    
    if (m_initialized) {
        return true;
    }
    
    // Create directory if it doesn't exist
    size_t last_slash = db_path.find_last_of("/");
    if (last_slash != std::string::npos) {
        std::string dir_path = db_path.substr(0, last_slash);
        mkdir(dir_path.c_str(), 0755);
    }
    
    int rc = sqlite3_open(db_path.c_str(), &m_db);
    if (rc) {
        sls_log(SLS_LOG_ERROR, "[CSLSDatabase] Can't open database: %s", sqlite3_errmsg(m_db));
        sqlite3_close(m_db);
        m_db = nullptr;
        return false;
    }
    
    if (!initSchema()) {
        close();
        return false;
    }
    
    insertDefaultApiKey();
    m_initialized = true;
    
    sls_log(SLS_LOG_INFO, "[CSLSDatabase] Database initialized at: %s", db_path.c_str());
    return true;
}

void CSLSDatabase::close() {
    std::lock_guard<std::mutex> lock(m_db_mutex);
    if (m_db) {
        sqlite3_close(m_db);
        m_db = nullptr;
    }
    m_initialized = false;
}

bool CSLSDatabase::initSchema() {
    const char* sql = R"(
        CREATE TABLE IF NOT EXISTS stream_ids (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            publisher TEXT NOT NULL,
            player TEXT NOT NULL UNIQUE,
            description TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(publisher, player)
        );
        
        CREATE TABLE IF NOT EXISTS api_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key_hash TEXT UNIQUE NOT NULL,
            name TEXT NOT NULL,
            permissions TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            last_used DATETIME,
            active BOOLEAN DEFAULT 1
        );
        
        CREATE TABLE IF NOT EXISTS access_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            api_key_id INTEGER,
            endpoint TEXT NOT NULL,
            method TEXT NOT NULL,
            ip_address TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            response_code INTEGER,
            FOREIGN KEY (api_key_id) REFERENCES api_keys(id)
        );
        
        CREATE INDEX IF NOT EXISTS idx_stream_publisher ON stream_ids(publisher);
        CREATE INDEX IF NOT EXISTS idx_stream_player ON stream_ids(player);
        CREATE INDEX IF NOT EXISTS idx_api_key_hash ON api_keys(key_hash);
        CREATE INDEX IF NOT EXISTS idx_access_logs_timestamp ON access_logs(timestamp);
    )";
    
    char* err_msg = nullptr;
    int rc = sqlite3_exec(m_db, sql, nullptr, nullptr, &err_msg);
    if (rc != SQLITE_OK) {
        sls_log(SLS_LOG_ERROR, "[CSLSDatabase] SQL error: %s", err_msg);
        sqlite3_free(err_msg);
        return false;
    }
    
    return true;
}

std::string CSLSDatabase::hashApiKey(const std::string& key) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)key.c_str(), key.size(), hash);
    
    std::stringstream ss;
    for(int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return ss.str();
}

std::string CSLSDatabase::generateApiKey() {
    const char charset[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    const int key_length = 32;
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, sizeof(charset) - 2);
    
    std::string key;
    for (int i = 0; i < key_length; i++) {
        key += charset[dis(gen)];
    }
    return key;
}

void CSLSDatabase::insertDefaultApiKey() {
    // Check if any API key exists
    const char* check_sql = "SELECT COUNT(*) FROM api_keys";
    sqlite3_stmt* stmt;
    sqlite3_prepare_v2(m_db, check_sql, -1, &stmt, nullptr);
    sqlite3_step(stmt);
    int count = sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt);
    
    if (count == 0) {
        // Generate and insert default admin key
        std::string api_key = generateApiKey();
        std::string key_hash = hashApiKey(api_key);
        
        const char* insert_sql = "INSERT INTO api_keys (key_hash, name, permissions) VALUES (?, ?, ?)";
        sqlite3_prepare_v2(m_db, insert_sql, -1, &stmt, nullptr);
        sqlite3_bind_text(stmt, 1, key_hash.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, "Default Admin Key", -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 3, "admin", -1, SQLITE_STATIC);
        
        if (sqlite3_step(stmt) == SQLITE_DONE) {
            sls_log(SLS_LOG_INFO, "[CSLSDatabase] ============================================");
            sls_log(SLS_LOG_INFO, "[CSLSDatabase] Generated default admin API key: %s", api_key.c_str());
            sls_log(SLS_LOG_INFO, "[CSLSDatabase] IMPORTANT: Save this key securely. It will not be shown again.");
            sls_log(SLS_LOG_INFO, "[CSLSDatabase] ============================================");
        }
        sqlite3_finalize(stmt);
    }
}

bool CSLSDatabase::verifyApiKey(const std::string& api_key, std::string& permissions) {
    std::lock_guard<std::mutex> lock(m_db_mutex);
    
    if (!m_initialized) return false;
    
    std::string key_hash = hashApiKey(api_key);
    const char* sql = "SELECT id, permissions FROM api_keys WHERE key_hash = ? AND active = 1";
    sqlite3_stmt* stmt;
    
    sqlite3_prepare_v2(m_db, sql, -1, &stmt, nullptr);
    sqlite3_bind_text(stmt, 1, key_hash.c_str(), -1, SQLITE_STATIC);
    
    bool valid = false;
    int key_id = -1;
    
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        valid = true;
        key_id = sqlite3_column_int(stmt, 0);
        permissions = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
    }
    sqlite3_finalize(stmt);
    
    // Update last_used timestamp
    if (valid) {
        const char* update_sql = "UPDATE api_keys SET last_used = CURRENT_TIMESTAMP WHERE id = ?";
        sqlite3_prepare_v2(m_db, update_sql, -1, &stmt, nullptr);
        sqlite3_bind_int(stmt, 1, key_id);
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
    }
    
    return valid;
}

void CSLSDatabase::logAccess(const std::string& api_key, const std::string& endpoint, 
                             const std::string& method, const std::string& ip, int response_code) {
    std::lock_guard<std::mutex> lock(m_db_mutex);
    
    if (!m_initialized) return;
    
    // Get API key ID
    std::string key_hash = hashApiKey(api_key);
    const char* get_id_sql = "SELECT id FROM api_keys WHERE key_hash = ?";
    sqlite3_stmt* stmt;
    
    sqlite3_prepare_v2(m_db, get_id_sql, -1, &stmt, nullptr);
    sqlite3_bind_text(stmt, 1, key_hash.c_str(), -1, SQLITE_STATIC);
    
    int key_id = -1;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        key_id = sqlite3_column_int(stmt, 0);
    }
    sqlite3_finalize(stmt);
    
    // Insert log entry
    const char* log_sql = "INSERT INTO access_logs (api_key_id, endpoint, method, ip_address, response_code) VALUES (?, ?, ?, ?, ?)";
    sqlite3_prepare_v2(m_db, log_sql, -1, &stmt, nullptr);
    sqlite3_bind_int(stmt, 1, key_id);
    sqlite3_bind_text(stmt, 2, endpoint.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, method.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 4, ip.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 5, response_code);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
}

json CSLSDatabase::getStreamIds() {
    std::lock_guard<std::mutex> lock(m_db_mutex);
    
    json result = json::array();
    if (!m_initialized) return result;
    
    const char* sql = "SELECT publisher, player, description FROM stream_ids ORDER BY publisher, player";
    sqlite3_stmt* stmt;
    
    sqlite3_prepare_v2(m_db, sql, -1, &stmt, nullptr);
    
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        json stream;
        stream["publisher"] = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        stream["player"] = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        const char* desc = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        if (desc) stream["description"] = desc;
        result.push_back(stream);
    }
    
    sqlite3_finalize(stmt);
    return result;
}

bool CSLSDatabase::addStreamId(const std::string& publisher, const std::string& player, const std::string& description) {
    std::lock_guard<std::mutex> lock(m_db_mutex);
    
    const char* sql = "INSERT INTO stream_ids (publisher, player, description, updated_at) VALUES (?, ?, ?, CURRENT_TIMESTAMP)";
    sqlite3_stmt* stmt;
    
    sqlite3_prepare_v2(m_db, sql, -1, &stmt, nullptr);
    sqlite3_bind_text(stmt, 1, publisher.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, player.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, description.c_str(), -1, SQLITE_STATIC);
    
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    
    if (rc != SQLITE_DONE) {
        // Check if it's a unique constraint violation
        if (rc == SQLITE_CONSTRAINT) {
            sls_log(SLS_LOG_WARNING, "[CSLSDatabase] Stream ID with player '%s' already exists", player.c_str());
        } else {
            sls_log(SLS_LOG_ERROR, "[CSLSDatabase] Failed to add stream ID: %s", sqlite3_errmsg(m_db));
        }
        return false;
    }
    
    return true;
}

bool CSLSDatabase::deleteStreamId(const std::string& player) {
    std::lock_guard<std::mutex> lock(m_db_mutex);
    
    if (!m_initialized) return false;
    
    const char* sql = "DELETE FROM stream_ids WHERE player = ?";
    sqlite3_stmt* stmt;
    
    sqlite3_prepare_v2(m_db, sql, -1, &stmt, nullptr);
    sqlite3_bind_text(stmt, 1, player.c_str(), -1, SQLITE_STATIC);
    
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    
    return rc == SQLITE_DONE && sqlite3_changes(m_db) > 0;
}

json CSLSDatabase::getStreamIdMapping() {
    std::lock_guard<std::mutex> lock(m_db_mutex);
    
    json mapping = json::object();
    if (!m_initialized) return mapping;
    
    const char* sql = "SELECT publisher, player FROM stream_ids";
    sqlite3_stmt* stmt;
    
    sqlite3_prepare_v2(m_db, sql, -1, &stmt, nullptr);
    
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        std::string publisher = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        std::string player = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        mapping[publisher] = player;
    }
    
    sqlite3_finalize(stmt);
    return mapping;
}

std::string CSLSDatabase::getPublisherFromPlayer(const std::string& player_id) {
    std::lock_guard<std::mutex> lock(m_db_mutex);
    
    const char* sql = "SELECT publisher FROM stream_ids WHERE player = ?";
    sqlite3_stmt* stmt;
    
    sqlite3_prepare_v2(m_db, sql, -1, &stmt, nullptr);
    sqlite3_bind_text(stmt, 1, player_id.c_str(), -1, SQLITE_STATIC);
    
    std::string publisher;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        const char* pub = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        if (pub) {
            publisher = pub;
        }
    }
    
    sqlite3_finalize(stmt);
    return publisher;
}

bool CSLSDatabase::createApiKey(const std::string& name, const std::string& permissions, std::string& out_key) {
    std::lock_guard<std::mutex> lock(m_db_mutex);
    
    if (!m_initialized) return false;
    
    out_key = generateApiKey();
    std::string key_hash = hashApiKey(out_key);
    
    const char* sql = "INSERT INTO api_keys (key_hash, name, permissions) VALUES (?, ?, ?)";
    sqlite3_stmt* stmt;
    
    sqlite3_prepare_v2(m_db, sql, -1, &stmt, nullptr);
    sqlite3_bind_text(stmt, 1, key_hash.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, name.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, permissions.c_str(), -1, SQLITE_STATIC);
    
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    
    return rc == SQLITE_DONE;
}

bool CSLSDatabase::validateStreamId(const char* stream_id, bool is_publisher, char* mapped_id) {
    if (!m_initialized) {
        // Allow all if database is not available (fallback mode)
        return true;
    }
    
    try {
        auto stream_ids = getStreamIds();
        
        if (is_publisher) {
            // For publisher, check if the stream ID is a valid publisher ID
            for (const auto& stream : stream_ids) {
                if (stream["publisher"] == stream_id) {
                    return true;
                }
            }
            return false;
        } else {
            // For player, check if the stream ID is a valid player ID and get mapped publisher ID
            for (const auto& stream : stream_ids) {
                if (stream["player"] == stream_id) {
                    if (mapped_id != nullptr) {
                        strcpy(mapped_id, stream["publisher"].get<std::string>().c_str());
                    }
                    return true;
                }
            }
            return false;
        }
    } catch (const std::exception& e) {
        sls_log(SLS_LOG_ERROR, "[CSLSDatabase] Error validating stream ID: %s", e.what());
        return true; // Allow in case of error
    }
} 