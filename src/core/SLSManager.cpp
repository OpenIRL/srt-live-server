
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

#include <errno.h>
#include <string.h>
#include "spdlog/spdlog.h"

#include <nlohmann/json.hpp>
using json = nlohmann::json;

#include "common.hpp"
#include "SLSManager.hpp"
#include "SLSLog.hpp"
#include "SLSListener.hpp"
#include "SLSPublisher.hpp"

/**
 * srt conf
 */
SLS_CONF_DYNAMIC_IMPLEMENT(srt)

/**
 * CSLSManager class implementation
 */
#define DEFAULT_GROUP 1

CSLSManager::CSLSManager()
{
    m_worker_threads = DEFAULT_GROUP;
    m_server_count = 1;
    m_list_role = NULL;
    m_single_group = NULL;

    m_map_data = NULL;
    m_map_publisher = NULL;
    m_map_puller = NULL;
    m_map_pusher = NULL;
}

CSLSManager::~CSLSManager()
{
}

int CSLSManager::start()
{
    int ret = 0;
    int i = 0;

    // Read loaded config file
    sls_conf_srt_t *conf_srt = (sls_conf_srt_t *)sls_conf_get_root_conf();

    if (!conf_srt)
    {
        spdlog::error("[{}] CSLSManager::start, no srt info, please check the conf file.", fmt::ptr(this));
        return SLS_ERROR;
    }
    //set log level
    if (strlen(conf_srt->log_level) > 0)
    {
        sls_set_log_level(conf_srt->log_level);
    }
    //set log file
    if (strlen(conf_srt->log_file) > 0)
    {
        sls_set_log_file(conf_srt->log_file);
    }

    sls_conf_server_t *conf_server = (sls_conf_server_t *)conf_srt->child;
    if (!conf_server)
    {
        spdlog::error("[{}] CSLSManager::start, no server info, please check the conf file.", fmt::ptr(this));
        return SLS_ERROR;
    }
    m_server_count = sls_conf_get_conf_count((sls_conf_base_t *)conf_server);
    sls_conf_server_t *conf = conf_server;
    m_map_data = new CSLSMapData[m_server_count];
    m_map_publisher = new CSLSMapPublisher[m_server_count];
    m_map_puller = new CSLSMapRelay[m_server_count];
    m_map_pusher = new CSLSMapRelay[m_server_count];

    //role list
    m_list_role = new CSLSRoleList;
    spdlog::info("[{}] CSLSManager::start, new m_list_role={}.", fmt::ptr(this), fmt::ptr(m_list_role));

    //create listeners according config, delete by groups
    for (i = 0; i < m_server_count; i++)
    {
        CSLSListener *p = new CSLSListener(); //deleted by groups
        p->set_role_list(m_list_role);
        p->set_conf((sls_conf_base_t *)conf);
        p->set_record_hls_path_prefix(conf_srt->record_hls_path_prefix);
        p->set_map_data("", &m_map_data[i]);
        p->set_map_publisher(&m_map_publisher[i]);
        p->set_map_puller(&m_map_puller[i]);
        p->set_map_pusher(&m_map_pusher[i]);
        if (p->init() != SLS_OK)
        {
            spdlog::error("[{}] CSLSManager::start, p->init failed.", fmt::ptr(this));
            return SLS_ERROR;
        }
        if (p->start() != SLS_OK)
        {
            spdlog::error("[{}] CSLSManager::start, p->start failed.", fmt::ptr(this));
            return SLS_ERROR;
        }
        m_servers.push_back(p);
        conf = (sls_conf_server_t *)conf->sibling;
    }
    spdlog::info("[{}] CSLSManager::start, init listeners, count={:d}.", fmt::ptr(this), m_server_count);

    //create groups

    m_worker_threads = conf_srt->worker_threads;
    if (m_worker_threads == 0)
    {
        CSLSGroup *p = new CSLSGroup();
        p->set_worker_number(0);
        p->set_role_list(m_list_role);
        p->set_worker_connections(conf_srt->worker_connections);
        p->set_stat_post_interval(conf_srt->stat_post_interval);
        if (SLS_OK != p->init_epoll())
        {
            spdlog::error("[{}] CSLSManager::start, p->init_epoll failed.", fmt::ptr(this));
            return SLS_ERROR;
        }
        m_workers.push_back(p);
        m_single_group = p;
    }
    else
    {
        for (i = 0; i < m_worker_threads; i++)
        {
            CSLSGroup *p = new CSLSGroup();
            p->set_worker_number(i);
            p->set_role_list(m_list_role);
            p->set_worker_connections(conf_srt->worker_connections);
            p->set_stat_post_interval(conf_srt->stat_post_interval);
            if (SLS_OK != p->init_epoll())
            {
                spdlog::error("[{}] CSLSManager::start, p->init_epoll failed.", fmt::ptr(this));
                return SLS_ERROR;
            }
            p->start();
            m_workers.push_back(p);
        }
    }
    spdlog::info("[{}] CSLSManager::start, init worker, count={:d}.", fmt::ptr(this), m_worker_threads);

    return ret;
}

json CSLSManager::generate_json_for_publisher(std::string publisherName, int clear) {
    json ret;
    ret["status"] = "error";
    ret["message"] = "publisher not found";

    for (int i = 0; i < m_server_count; i++) {
        CSLSMapPublisher *publisher_map = &m_map_publisher[i];
        CSLSRole *role = publisher_map->get_publisher(publisherName);

        if (role == NULL) continue;

        ret["status"] = "ok";
        ret["publishers"][publisherName] = create_json_stats_for_publisher(role, clear);
        ret.erase("message");
        break;
    }

    return ret;
}


json CSLSManager::create_json_stats_for_publisher(CSLSRole *role, int clear) {
    json ret = json::object();
    SRT_TRACEBSTATS stats;
    role->get_statistics(&stats, clear);
    // Interval
    ret["pktRcvLoss"]       = stats.pktRcvLoss;
    ret["pktRcvDrop"]       = stats.pktRcvDrop;
    ret["bytesRcvLoss"]     = stats.byteRcvLoss;
    ret["bytesRcvDrop"]     = stats.byteRcvDrop;
    ret["mbpsRecvRate"]     = stats.mbpsRecvRate;
    // Instant
    ret["rtt"]              = stats.msRTT;
    ret["msRcvBuf"]         = stats.msRcvBuf;
    ret["mbpsBandwidth"]    = stats.mbpsBandwidth;
    ret["bitrate"]          = role->get_bitrate(); // in kbps
    ret["uptime"]           = role->get_uptime(); // in seconds
    return ret;
}


int CSLSManager::single_thread_handler()
{
    if (m_single_group)
    {
        return m_single_group->handler();
    }
    return SLS_OK;
}

bool CSLSManager::is_single_thread()
{
    if (m_single_group)
        return true;
    return false;
}

int CSLSManager::stop()
{
    int ret = 0;
    int i = 0;
    //
    spdlog::info("[{}] CSLSManager::stop.", fmt::ptr(this));

    //stop all listeners
    for (CSLSListener *server : m_servers)
    {
        if (server)
        {
            server->uninit();
        }
    }
    m_servers.clear();

    vector<CSLSGroup *>::iterator it_worker;
    for (it_worker = m_workers.begin(); it_worker != m_workers.end(); it_worker++)
    {
        CSLSGroup *p = *it_worker;
        if (p)
        {
            p->stop();
            p->uninit_epoll();
            delete p;
            p = NULL;
        }
    }
    m_workers.clear();

    if (m_map_data)
    {
        delete[] m_map_data;
        m_map_data = NULL;
    }
    if (m_map_publisher)
    {
        delete[] m_map_publisher;
        m_map_publisher = NULL;
    }

    if (m_map_puller)
    {
        delete[] m_map_puller;
        m_map_puller = NULL;
    }

    if (m_map_pusher)
    {
        delete[] m_map_pusher;
        m_map_pusher = NULL;
    }

    //release rolelist
    if (m_list_role)
    {
        spdlog::info("[{}] CSLSManager::stop, release rolelist, size={:d}.", fmt::ptr(this), m_list_role->size());
        m_list_role->erase();
        delete m_list_role;
        m_list_role = NULL;
    }
    return ret;
}

int CSLSManager::reload()
{
    spdlog::info("[{}] CSLSManager::reload begin.", fmt::ptr(this));

    // stop all listeners
    for (CSLSListener *server : m_servers)
    {
        if (server)
        {
            server->uninit();
        }
    }
    m_servers.clear();

    // set all groups reload flag
    for (CSLSGroup *worker : m_workers)
    {
        if (worker)
        {
            worker->reload();
        }
    }
    return 0;
}

int CSLSManager::check_invalid()
{
    vector<CSLSGroup *>::iterator it;
    vector<CSLSGroup *>::iterator it_erase;
    vector<CSLSGroup *>::iterator it_end = m_workers.end();
    for (it = m_workers.begin(); it != it_end;)
    {
        CSLSGroup *worker = *it;
        it_erase = it;
        it++;
        if (NULL == worker)
        {
            m_workers.erase(it_erase);
            continue;
        }
        if (worker->is_exit())
        {
            spdlog::info("[{}] CSLSManager::check_invalid, delete worker={}.",
                         fmt::ptr(this), fmt::ptr(worker));
            worker->stop();
            worker->uninit_epoll();
            delete worker;
            m_workers.erase(it_erase);
        }
    }

    if (m_workers.size() == 0)
        return SLS_OK;
    return SLS_ERROR;
}

std::string CSLSManager::get_stat_info()
{
    json info_obj;
    info_obj["stats"] = json::array();

    for (CSLSGroup *worker : m_workers)
    {
        if (worker)
        {
            vector<stat_info_t> worker_info;
            worker->get_stat_info(worker_info);

            for (stat_info_t &role_info : worker_info)
            {
                info_obj["stats"].push_back(json{
                    {"port", role_info.port},
                    {"role", role_info.role},
                    {"pub_domain_app", role_info.pub_domain_app},
                    {"stream_name", role_info.stream_name},
                    {"url", role_info.url},
                    {"remote_ip", role_info.remote_ip},
                    {"remote_port", role_info.remote_port},
                    {"start_time", role_info.start_time},
                    {"kbitrate", role_info.kbitrate}});
            }

        }
    }

    return info_obj.dump();
}

int CSLSManager::stat_client_callback(void *p, HTTP_CALLBACK_TYPE type, void *v, void *context)
{
    CSLSManager *manager = (CSLSManager *)context;
    if (HCT_REQUEST_CONTENT == type)
    {
        std::string *p_response = (std::string *)v;
        p_response->assign(manager->get_stat_info());
    }
    else if (HCT_RESPONSE_END == type)
    {
        //response info maybe include info that server send client, such as reload cmd...
    }
    else
    {
    }
    return SLS_OK;
}
