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

#ifndef _STREAMIDMAPPER_INCLUDE_
#define _STREAMIDMAPPER_INCLUDE_

#include <string>
#include <vector>
#include <map>
#include "SLSLock.hpp"

/**
 * StreamIdMapper - Thread-safe caching mapper for Stream ID authentication
 * 
 * Manages mapping between player and publisher stream IDs with automatic
 * cache invalidation when the JSON file changes.
 */
class StreamIdMapper {
public:
    static StreamIdMapper& getInstance();
    
    // Initialize with JSON file path
    bool init(const std::string& json_file_path);
    
    // Check if a publisher ID is valid
    bool isValidPublisher(const std::string& publisher_id);
    
    // Check if a player ID is valid and optionally get mapped publisher ID
    bool isValidPlayer(const std::string& player_id, std::string* publisher_id = nullptr);
    
    // Get publisher ID from player ID (returns empty string if not found)
    std::string getPublisherFromPlayer(const std::string& player_id);
    
    // Force reload of the JSON file
    bool reload();
    
    // Get cache statistics
    struct CacheStats {
        size_t mapping_count;
        time_t last_loaded;
        std::string file_path;
    };
    CacheStats getStats() const;

private:
    StreamIdMapper() = default;
    ~StreamIdMapper() = default;
    
    // Disable copy constructor and assignment
    StreamIdMapper(const StreamIdMapper&) = delete;
    StreamIdMapper& operator=(const StreamIdMapper&) = delete;
    
    struct StreamMapping {
        std::string player_id;
        std::string publisher_id;
    };
    
    // Internal methods
    bool loadMappings();
    time_t getFileModTime() const;
    
    // Thread safety
    mutable CSLSMutex m_mutex;
    
    // Cache data
    std::vector<StreamMapping> m_mappings;
    std::map<std::string, std::string> m_player_to_publisher;
    std::map<std::string, bool> m_valid_publishers;
    
    // File tracking
    std::string m_json_file_path;
    time_t m_last_mtime;
    bool m_initialized;
};

#endif // _STREAMIDMAPPER_INCLUDE_ 