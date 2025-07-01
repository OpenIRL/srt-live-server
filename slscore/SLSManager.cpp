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
#include <fstream>

#include "common.hpp"
#include "SLSManager.hpp"
#include "SLSLog.hpp"
#include "SLSListener.hpp"
#include "SLSPublisher.hpp"
#include "SLSMapData.hpp"
#include "SLSRelayManager.hpp"
#include "SLSPullerManager.hpp"
#include "SLSMapRelay.hpp"
#include "SLSPusherManager.hpp"
#include "SLSMapPublisher.hpp"
#include "SLSDatabase.hpp"

using json = nlohmann::json;

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
    m_list_role      = NULL;
    m_single_group   = NULL;

    m_map_data       = NULL;
    m_map_publisher  = NULL;
    m_map_puller     = NULL;
    m_map_pusher     = NULL;

}

CSLSManager::~CSLSManager()
{
}

int CSLSManager::start()
{
	int ret = 0;
	int i = 0;

    //read config info from config file
    sls_conf_srt_t * conf_srt = (sls_conf_srt_t *)sls_conf_get_root_conf();

    if (!conf_srt) {
        sls_log(SLS_LOG_INFO, "[%p]CSLSManager::start, no srt info, please check the conf file.", this);
        return SLS_ERROR;
    }
    //set log level
    if (strlen(conf_srt->log_level) > 0) {
        sls_set_log_level(conf_srt->log_level);
    }
    //set log file
    if (strlen(conf_srt->log_file) > 0) {
        sls_set_log_file(conf_srt->log_file);
    }

    sls_conf_server_t * conf_server = (sls_conf_server_t *)conf_srt->child;
    if (!conf_server) {
        sls_log(SLS_LOG_INFO, "[%p]CSLSManager::start, no server info, please check the conf file.", this);
        return SLS_ERROR;
    }
    m_server_count = sls_conf_get_conf_count(conf_server);
    sls_conf_server_t * conf = conf_server;
    m_map_data      = new CSLSMapData[m_server_count];
    m_map_publisher = new CSLSMapPublisher[m_server_count];
    m_map_puller    = new CSLSMapRelay[m_server_count];
    m_map_pusher    = new CSLSMapRelay[m_server_count];

    //role list
    m_list_role = new CSLSRoleList;
    sls_log(SLS_LOG_INFO, "[%p]CSLSManager::start, new m_list_role=%p.", this, m_list_role);

    //create listeners according config, delete by groups
    for (i = 0; i < m_server_count; i ++) {
        // Check if both ports are configured
        if (conf->listen_publisher <= 0 || conf->listen_player <= 0) {
            sls_log(SLS_LOG_ERROR, "[%p]CSLSManager::start, both listen_publisher and listen_player must be configured.", this);
            return SLS_ERROR;
        }
        
        // Create publisher listener
        CSLSListener * p_pub = new CSLSListener();//deleted by groups
        p_pub->set_role_list(m_list_role);
        p_pub->set_conf(conf);
        p_pub->set_record_hls_path_prefix(conf_srt->record_hls_path_prefix);
        p_pub->set_map_data("", &m_map_data[i]);
        p_pub->set_map_publisher(&m_map_publisher[i]);
        p_pub->set_map_puller(&m_map_puller[i]);
        p_pub->set_map_pusher(&m_map_pusher[i]);
        p_pub->set_listener_type(true); // Publisher listener
        if (p_pub->init() != SLS_OK) {
            sls_log(SLS_LOG_INFO, "[%p]CSLSManager::start, p_pub->init failed.", this);
            return SLS_ERROR;
        }
        if (p_pub->start() != SLS_OK) {
            sls_log(SLS_LOG_INFO, "[%p]CSLSManager::start, p_pub->start failed.", this);
            return SLS_ERROR;
        }
        m_servers.push_back(p_pub);
        
        // Create player listener
        CSLSListener * p_play = new CSLSListener();//deleted by groups
        p_play->set_role_list(m_list_role);
        p_play->set_conf(conf);
        p_play->set_record_hls_path_prefix(conf_srt->record_hls_path_prefix);
        p_play->set_map_data("", &m_map_data[i]);
        p_play->set_map_publisher(&m_map_publisher[i]);
        p_play->set_map_puller(&m_map_puller[i]);
        p_play->set_map_pusher(&m_map_pusher[i]);
        p_play->set_listener_type(false); // Player listener
        if (p_play->init() != SLS_OK) {
            sls_log(SLS_LOG_INFO, "[%p]CSLSManager::start, p_play->init failed.", this);
            return SLS_ERROR;
        }
        if (p_play->start() != SLS_OK) {
            sls_log(SLS_LOG_INFO, "[%p]CSLSManager::start, p_play->start failed.", this);
            return SLS_ERROR;
        }
        m_servers.push_back(p_play);
        
    	conf = (sls_conf_server_t *)conf->sibling;
    }
    sls_log(SLS_LOG_INFO, "[%p]CSLSManager::start, init listeners, count=%d.", this, m_servers.size());

    //create groups

    m_worker_threads = conf_srt->worker_threads;
    if (m_worker_threads == 0) {
        CSLSGroup * p = new CSLSGroup();
        p->set_worker_number(0);
        p->set_role_list(m_list_role);
        p->set_worker_connections(conf_srt->worker_connections);
        p->set_stat_post_interval(conf_srt->stat_post_interval);
        if (SLS_OK != p->init_epoll()) {
            sls_log(SLS_LOG_INFO, "[%p]CSLSManager::start, p->init_epoll failed.", this);
            return SLS_ERROR;
        }
        m_workers.push_back(p);
        m_single_group  =p;

    } else {
        for (i = 0; i < m_worker_threads; i ++) {
            CSLSGroup * p = new CSLSGroup();
            p->set_worker_number(i);
            p->set_role_list(m_list_role);
            p->set_worker_connections(conf_srt->worker_connections);
            p->set_stat_post_interval(conf_srt->stat_post_interval);
            if (SLS_OK != p->init_epoll()) {
                sls_log(SLS_LOG_INFO, "[%p]CSLSManager::start, p->init_epoll failed.", this);
                return SLS_ERROR;
            }
            p->start();
            m_workers.push_back(p);
        }
    }
    sls_log(SLS_LOG_INFO, "[%p]CSLSManager::start, init worker, count=%d.", this, m_worker_threads);

	return ret;

}

char* CSLSManager::find_publisher_by_player_key(char *player_key) {
    // First check stream ID database
    std::string publisher_id = CSLSDatabase::getInstance().getPublisherFromPlayer(player_key);
    if (!publisher_id.empty()) {
        static thread_local char mapped_publisher[512];
        strncpy(mapped_publisher, publisher_id.c_str(), sizeof(mapped_publisher) - 1);
        mapped_publisher[sizeof(mapped_publisher) - 1] = '\0';

        return mapped_publisher;
    }
    
    sls_log(SLS_LOG_WARNING, "[%p]CSLSManager::find_publisher_by_player_key, player key '%s' not found in database",
            this, player_key);
    
    // If not found in database, check if it's a direct publisher key
    CSLSRole* role = nullptr;
    for (int i = 0; i < m_server_count; i++) {
        role = m_map_publisher[i].get_publisher(player_key);
        if (role != nullptr) {
            break;
        }
    }
    
    if (role != NULL) {
        sls_log(SLS_LOG_INFO, "[%p]CSLSManager::find_publisher_by_player_key, player key '%s' is a publisher key",
                this, player_key);
        return player_key;
    }
    
    sls_log(SLS_LOG_WARNING, "[%p]CSLSManager::find_publisher_by_player_key, no publisher found for player key '%s'",
            this, player_key);
    return NULL;
}

json CSLSManager::generate_json_for_publisher(std::string playerKey, int clear) {
    json ret;
    ret["status"] = "error";

    // Validate input
    if (playerKey.empty()) {
        ret["message"] = "Player key is required";
        sls_log(SLS_LOG_WARNING, "[%p]CSLSManager::generate_json_for_publisher, empty player key provided", this);
        return ret;
    }

    // Validate player key and get mapped publisher key
    char* mapped_publisher = find_publisher_by_player_key(const_cast<char*>(playerKey.c_str()));
    if (mapped_publisher == NULL) {
        ret["message"] = "Invalid player key";
        sls_log(SLS_LOG_WARNING, "[%p]CSLSManager::generate_json_for_publisher, invalid player key: %s", 
                this, playerKey.c_str());
        return ret;
    }
    
    std::string publisher_key(mapped_publisher);

    ret["publishers"] = json::object();
    ret["status"] = "ok";

    // Search for active publisher
    CSLSRole *role = nullptr;
    for (int i = 0; i < m_server_count; i++) {
        CSLSMapPublisher *publisher_map = &m_map_publisher[i];
        role = publisher_map->get_publisher(publisher_key.c_str());
        if (role != nullptr) {
            break;
        }
    }

    if (role == nullptr) {
        ret["message"] = "Publisher is currently not streaming";
        sls_log(SLS_LOG_DEBUG, "[%p]CSLSManager::generate_json_for_publisher, publisher not found: %s (mapped from player key: %s)",
                this, publisher_key.c_str(), playerKey.c_str());
        return ret;
    }

    // Success - return publisher statistics
    ret["publishers"] = json::object();
    ret["publishers"]["live"] = create_json_stats_for_publisher(role, clear);
    ret.erase("message");
    
    sls_log(SLS_LOG_DEBUG, "[%p]CSLSManager::generate_json_for_publisher, returning stats for publisher: %s (player key: %s)", 
            this, publisher_key.c_str(), playerKey.c_str());
    
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
    ret["latency"]          = role->get_latency(); // in ms
    return ret;
}

int CSLSManager::single_thread_handler()
{
    if (m_single_group) {
        return m_single_group->handler();
    }
    return SLS_OK;
}

bool CSLSManager::is_single_thread(){
    if (m_single_group)
        return true;
    return false;
}

int CSLSManager::stop()
{
	int ret = 0;
	int i = 0;
    //
    sls_log(SLS_LOG_INFO, "[%p]CSLSManager::stop.", this);

    //stop all listeners
    std::list<CSLSListener *>::iterator it;
    for ( it = m_servers.begin(); it != m_servers.end(); it++) {
    	CSLSListener *server = *it;
    	if (NULL == server) {
    		continue;
    	}
    	server->uninit();
    }
    m_servers.clear();

    std::list<CSLSGroup *>::iterator it_worker;
    for ( it_worker = m_workers.begin(); it_worker != m_workers.end(); it_worker++) {
    	CSLSGroup *worker = *it_worker;
    	if (worker) {
    		worker->stop();
    		worker->uninit_epoll();
    		delete worker;
    		worker = NULL;
    	}
    }
    m_workers.clear();

    if (m_map_data) {
    	delete[] m_map_data;
    	m_map_data = NULL;
    }
    if (m_map_publisher) {
    	delete[] m_map_publisher;
    	m_map_publisher = NULL;
    }

    if (m_map_puller) {
    	delete[] m_map_puller;
    	m_map_puller = NULL;
    }

    if (m_map_pusher) {
    	delete[] m_map_pusher;
    	m_map_pusher = NULL;
    }

    //release rolelist
    if(m_list_role) {
        sls_log(SLS_LOG_INFO, "[%p]CSLSManager::stop, release rolelist, size=%d.", this, m_list_role->size());
    	m_list_role->erase();
    	delete m_list_role;
    	m_list_role = NULL;
    }
    return ret;
}

int CSLSManager::reload()
{
    sls_log(SLS_LOG_INFO, "[%p]CSLSManager::reload begin.", this);

    //stop all listeners
    std::list<CSLSListener *>::iterator it;
    for ( it = m_servers.begin(); it != m_servers.end(); it++) {
    	CSLSListener *server = *it;
    	if (NULL == server) {
    		continue;
    	}
    	server->uninit();
    }
    m_servers.clear();

    //set all groups reload flag
    std::list<CSLSGroup *>::iterator it_worker;
    for ( it_worker = m_workers.begin(); it_worker != m_workers.end(); it_worker++) {
    	CSLSGroup *worker = *it_worker;
    	if (worker) {
    		worker->reload();
    	}
    }
	return 0;
}

int  CSLSManager::check_invalid()
{
    std::list<CSLSGroup *>::iterator it;
    std::list<CSLSGroup *>::iterator it_erase;
    std::list<CSLSGroup *>::iterator it_end = m_workers.end();
    for ( it = m_workers.begin(); it != it_end; ) {
    	CSLSGroup *worker = *it;
    	it_erase = it;
    	it++;
    	if (NULL == worker) {
			m_workers.erase(it_erase);
			continue;
    	}
		if (worker->is_exit()) {
			sls_log(SLS_LOG_INFO, "[%p]CSLSManager::check_invalid, delete worker=%p.",
					this, worker);
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

void CSLSManager::get_stat_info(std::string &info)
{
    std::list<CSLSGroup *>::iterator it;
    std::list<CSLSGroup *>::iterator it_end = m_workers.end();
    for ( it = m_workers.begin(); it != it_end; ) {
    	CSLSGroup *worker = *it;
    	it++;
    	if (NULL != worker) {
    		worker->get_stat_info(info);
    	}
    }
}

int  CSLSManager::stat_client_callback(void *p, HTTP_CALLBACK_TYPE type, void *v, void* context)
{
	CSLSManager *manager = (CSLSManager *)context;
	if (HCT_REQUEST_CONTENT == type) {
		std::string * p_response = (std::string *)v;
		manager->get_stat_info(*p_response);
	} else if (HCT_RESPONSE_END == type) {
		//response info maybe include info that server send client, such as reload cmd...
	} else {

	}
	return SLS_OK;
}



