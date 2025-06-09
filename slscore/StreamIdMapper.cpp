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

#include "StreamIdMapper.hpp"
#include "SLSLog.hpp"
#include "json.hpp"
#include <fstream>
#include <sys/stat.h>

using json = nlohmann::json;

StreamIdMapper& StreamIdMapper::getInstance() {
    static StreamIdMapper instance;
    return instance;
}

bool StreamIdMapper::init(const std::string& json_file_path) {
    CSLSLock lock(&m_mutex);
    
    m_json_file_path = json_file_path;
    m_last_mtime = 0;
    m_initialized = false;
    
    // Clear existing data
    m_mappings.clear();
    m_player_to_publisher.clear();
    m_valid_publishers.clear();
    
    // Load initial mappings
    if (loadMappings()) {
        m_initialized = true;
        sls_log(SLS_LOG_INFO, "StreamIdMapper::init, initialized with %d mappings from %s", 
                (int)m_mappings.size(), m_json_file_path.c_str());
        return true;
    }
    
    sls_log(SLS_LOG_ERROR, "StreamIdMapper::init, failed to load mappings from %s", 
            m_json_file_path.c_str());
    return false;
}

bool StreamIdMapper::isValidPublisher(const std::string& publisher_id) {
    CSLSLock lock(&m_mutex);
    
    if (!m_initialized) {
        return false;
    }
    
    // Check if cache needs refresh
    time_t current_mtime = getFileModTime();
    if (current_mtime != m_last_mtime) {
        loadMappings();
    }
    
    return m_valid_publishers.find(publisher_id) != m_valid_publishers.end();
}

bool StreamIdMapper::isValidPlayer(const std::string& player_id, std::string* publisher_id) {
    CSLSLock lock(&m_mutex);
    
    if (!m_initialized) {
        return false;
    }
    
    // Check if cache needs refresh
    time_t current_mtime = getFileModTime();
    if (current_mtime != m_last_mtime) {
        loadMappings();
    }
    
    auto it = m_player_to_publisher.find(player_id);
    if (it != m_player_to_publisher.end()) {
        if (publisher_id != nullptr) {
            *publisher_id = it->second;
        }
        return true;
    }
    
    return false;
}

std::string StreamIdMapper::getPublisherFromPlayer(const std::string& player_id) {
    std::string publisher_id;
    if (isValidPlayer(player_id, &publisher_id)) {
        return publisher_id;
    }
    return "";
}

bool StreamIdMapper::reload() {
    CSLSLock lock(&m_mutex);
    
    if (!m_initialized) {
        return false;
    }
    
    m_last_mtime = 0; // Force reload
    return loadMappings();
}

StreamIdMapper::CacheStats StreamIdMapper::getStats() const {
    CSLSLock lock(&m_mutex);
    
    CacheStats stats;
    stats.mapping_count = m_mappings.size();
    stats.last_loaded = m_last_mtime;
    stats.file_path = m_json_file_path;
    
    return stats;
}

bool StreamIdMapper::loadMappings() {
    // Note: Caller must hold mutex
    
    if (m_json_file_path.empty()) {
        return false;
    }
    
    time_t current_mtime = getFileModTime();
    if (current_mtime == 0) {
        sls_log(SLS_LOG_WARNING, "StreamIdMapper::loadMappings, cannot stat file %s", 
                m_json_file_path.c_str());
        return false;
    }
    
    // Check if file hasn't changed
    if (current_mtime == m_last_mtime && !m_mappings.empty()) {
        return true; // Cache is still valid
    }
    
    // Load and parse JSON file
    std::ifstream file(m_json_file_path);
    if (!file.is_open()) {
        sls_log(SLS_LOG_WARNING, "StreamIdMapper::loadMappings, cannot open %s", 
                m_json_file_path.c_str());
        return false;
    }
    
    try {
        json j;
        file >> j;
        file.close();
        
        // Clear existing data
        m_mappings.clear();
        m_player_to_publisher.clear();
        m_valid_publishers.clear();
        
        // Parse JSON array
        for (const auto& mapping : j) {
            if (!mapping.contains("player") || !mapping.contains("publisher") ||
                !mapping["player"].is_string() || !mapping["publisher"].is_string()) {
                continue;
            }
            
            std::string player_id = mapping["player"].get<std::string>();
            std::string publisher_id = mapping["publisher"].get<std::string>();
            
            // Add to mappings vector
            StreamMapping stream_mapping;
            stream_mapping.player_id = player_id;
            stream_mapping.publisher_id = publisher_id;
            m_mappings.push_back(stream_mapping);
            
            // Add to lookup maps for fast access
            m_player_to_publisher[player_id] = publisher_id;
            m_valid_publishers[publisher_id] = true;
        }
        
        m_last_mtime = current_mtime;
        
        sls_log(SLS_LOG_INFO, "StreamIdMapper::loadMappings, loaded %d mappings from %s", 
                (int)m_mappings.size(), m_json_file_path.c_str());
        
        return true;
        
    } catch (const std::exception& e) {
        sls_log(SLS_LOG_ERROR, "StreamIdMapper::loadMappings, JSON parsing error: %s", e.what());
        return false;
    }
}

time_t StreamIdMapper::getFileModTime() const {
    struct stat file_stat;
    if (stat(m_json_file_path.c_str(), &file_stat) == 0) {
        return file_stat.st_mtime;
    }
    return 0;
} 