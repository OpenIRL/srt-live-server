/**
 * The MIT License (MIT)
 *
 * Copyright (c) 2019-2020 Edward.Wu
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

#pragma once

#include <map>
#include <string>

#include "conf.hpp"
#include "SLSLock.hpp"
#include "SLSRole.hpp"

class CSLSMapPublisher
{
public:
    CSLSMapPublisher();
    virtual ~CSLSMapPublisher();

    int set_conf(std::string key, sls_conf_base_t *ca);
    int set_live_2_uplive(std::string strLive, std::string strUplive);
    int set_push_2_pushlisher(std::string app_streamname, CSLSRole *role);
    int remove(CSLSRole *role);
    void clear();

    std::string get_uplive(std::string key_app);
    sls_conf_base_t *get_ca(std::string key_app);

    CSLSRole *get_publisher(std::string strAppStreamName);
    std::vector<std::string> get_publisher_names();

    CSLSRole* get_role_by_endpoint(const std::string& outgest) {
        CSLSLock lock(&m_rwclock, false);
        
        for (auto& item : m_map_publisher) {
            CSLSRole* role = item.second;
            if (!role || !role->get_srt()) continue;

            SRTSOCKET socket_id = role->get_srt()->get_socket();
            char streamid[512] = {0};
            int streamid_size = 512;
            
            if (srt_getsockflag(socket_id, SRTO_STREAMID, streamid, &streamid_size) == SRT_SUCCESS) {
                if (strcmp(streamid, outgest.c_str()) == 0) {
                    return role;
                }
            }
        }
        return nullptr;
    }

private:
    std::map<std::string, std::string> m_map_live_2_uplive;       // 'hostname/live':'hostname/uplive'
    std::map<std::string, sls_conf_base_t *> m_map_uplive_2_conf; // 'hostname/uplive':sls_app_conf_t
    std::map<std::string, CSLSRole *> m_map_push_2_pushlisher;    // 'hostname/uplive/steam_name':publisher'

    CSLSRWLock m_rwclock;
};
