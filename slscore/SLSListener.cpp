
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
#include <vector>
#include <fstream>
#include "json.hpp"

#include "SLSListener.hpp"
#include "SLSLog.hpp"
#include "SLSPublisher.hpp"
#include "SLSPlayer.hpp"
#include "SLSPullerManager.hpp"
#include "SLSPusherManager.hpp"
#include "StreamIdMapper.hpp"

using json = nlohmann::json;

const char SLS_SERVER_STAT_INFO_BASE[] = "\
{\
\"port\": \"%d\",\
\"role\": \"%s\",\
\"stream_name\": \"\",\
\"url\": \"\",\
\"remote_ip\": \"\",\
\"remote_port\": \"\",\
\"start_time\": \"%s\",\
\"kbitrate\": \"0\"\
}";

const char SLS_PUBLISHER_STAT_INFO_BASE[] = "\
{\
\"port\": \"%d\",\
\"role\": \"%s\",\
\"stream_name\": \"%s\",\
\"url\": \"%s\",\
\"remote_ip\": \"%s\",\
\"remote_port\": \"%d\",\
\"start_time\": \"%s\",\
\"kbitrate\":\
";

const char SLS_PLAYER_STAT_INFO_BASE[] = "\
{\
\"port\": \"%d\",\
\"role\": \"%s\",\
\"stream_name\": \"%s\",\
\"url\": \"%s\",\
\"remote_ip\": \"%s\",\
\"remote_port\": \"%d\",\
\"start_time\": \"%s\",\
\"kbitrate\":\
";

/**
 * server conf
 */
SLS_CONF_DYNAMIC_IMPLEMENT(server)

/**
 * CSLSListener class implementation
 */

CSLSListener::CSLSListener()
{
    m_conf      = NULL;
    m_back_log  = 1024;
    m_is_write  = 0;
    m_port      = 0;

    m_list_role     = NULL;
    m_map_publisher = NULL;
    m_map_puller    = NULL;
    m_map_pusher    = NULL;
    m_idle_streams_timeout      = UNLIMITED_TIMEOUT;
    m_idle_streams_timeout_role = 0;
    m_stat_info = std::string("");
    memset(m_http_url_role, 0, URL_MAX_LEN);
    memset(m_record_hls_path_prefix, 0, URL_MAX_LEN);
    m_is_publisher_listener = false;
    // Default path, will be overridden by configuration
    strcpy(m_stream_id_json_path, "/etc/sls/streamids.json");

    sprintf(m_role_name, "listener");
}

CSLSListener::~CSLSListener()
{
}

int CSLSListener::init()
{
	int ret = 0;
    return CSLSRole::init();
}

int CSLSListener::uninit()
{
	CSLSLock lock(&m_mutex);
    stop();
    return CSLSRole::uninit();
}

void CSLSListener::set_role_list(CSLSRoleList *list_role)
{
	m_list_role = list_role;
}

void CSLSListener::set_map_publisher(CSLSMapPublisher * publisher)
{
	m_map_publisher = publisher;
}

void CSLSListener::set_map_puller(CSLSMapRelay *map_puller)
{
    m_map_puller     = map_puller;
}

void CSLSListener::set_map_pusher(CSLSMapRelay *map_pusher)
{
    m_map_pusher     = map_pusher;
}

void CSLSListener::set_record_hls_path_prefix(char *path)
{
    if (path != NULL && strlen(path) > 0) {
        strcpy(m_record_hls_path_prefix, path);
    }
}

void CSLSListener::set_listener_type(bool is_publisher)
{
    m_is_publisher_listener = is_publisher;
    if (is_publisher) {
        sprintf(m_role_name, "listener-publisher");
    } else {
        sprintf(m_role_name, "listener-player");
    }
}

int CSLSListener::init_conf_app()
{
    sls_conf_server_t * conf_server;

    if (NULL == m_map_puller) {
        sls_log(SLS_LOG_ERROR, "[%p]CSLSListener::init_conf_app failed, m_map_puller is null.", this);
        return SLS_ERROR;
    }

    if (NULL == m_map_pusher) {
        sls_log(SLS_LOG_ERROR, "[%p]CSLSListener::init_conf_app failed, m_map_pusher is null.", this);
        return SLS_ERROR;
    }

    if (!m_conf) {
        sls_log(SLS_LOG_ERROR, "[%p]CSLSListener::init_conf_app failed, conf is null.", this);
        return SLS_ERROR;
    }
    conf_server = (sls_conf_server_t *)m_conf;

    m_back_log                   = conf_server->backlog;
    m_idle_streams_timeout_role  = conf_server->idle_streams_timeout;
    strcpy(m_http_url_role, conf_server->on_event_url);
    
    // Load stream IDs file path from configuration and initialize StreamIdMapper
    if (strlen(conf_server->stream_ids_file) > 0) {
        strcpy(m_stream_id_json_path, conf_server->stream_ids_file);
        sls_log(SLS_LOG_INFO, "[%p]CSLSListener::init_conf_app, using stream_ids_file='%s'.", 
                this, m_stream_id_json_path);
    } else {
        sls_log(SLS_LOG_INFO, "[%p]CSLSListener::init_conf_app, no stream_ids_file configured, using default='%s'.", 
                this, m_stream_id_json_path);
    }
    
    // Initialize StreamIdMapper singleton
    if (!StreamIdMapper::getInstance().init(std::string(m_stream_id_json_path))) {
        sls_log(SLS_LOG_WARNING, "[%p]CSLSListener::init_conf_app, failed to initialize StreamIdMapper with file='%s'.", 
                this, m_stream_id_json_path);
    }
    
    sls_log(SLS_LOG_INFO, "[%p]CSLSListener::init_conf_app, m_back_log=%d, m_idle_streams_timeout=%d.",
            this, m_back_log, m_idle_streams_timeout_role);

    // Simplified: No domain/app configuration needed anymore
    // Stream IDs are used directly without domain/app prefixes

    // Handle relay configuration if present
    sls_conf_relay_t * cr = (sls_conf_relay_t *)conf_server->child;
    if (cr) {
        while (cr) {
            if (strcmp(cr->type, "pull") == 0 ) {
                if (SLS_OK != m_map_puller->add_relay_conf("default", cr)) {
                    sls_log(SLS_LOG_WARNING, "[%p]CSLSListener::init_conf_app, m_map_puller.add_app_conf failed. relay type='%s'.",
                            this, cr->type);
                }
            }
            else if (strcmp(cr->type, "push") == 0) {
                if (SLS_OK != m_map_pusher->add_relay_conf("default", cr)) {
                    sls_log(SLS_LOG_WARNING, "[%p]CSLSListener::init_conf_app, m_map_pusher.add_app_conf failed. relay type='%s'.",
                            this, cr->type);
                }
            } else {
                sls_log(SLS_LOG_ERROR, "[%p]CSLSListener::init_conf_app, wrong relay type='%s'.",
                        this, cr->type);
                return SLS_ERROR;
            }
            cr = (sls_conf_relay_t *)cr->sibling;
        }
    }

    return SLS_OK;
}

int CSLSListener::start()
{
	int ret = 0;
    std::string strLive;
    std::string strUplive;
    std::string strLiveDomain;
    std::string strUpliveDomain;


	if (NULL == m_conf) {
	    sls_log(SLS_LOG_ERROR, "[%p]CSLSListener::start failed, conf is null.", this);
	    return SLS_ERROR;
	}
    sls_log(SLS_LOG_INFO, "[%p]CSLSListener::start...", this);

    ret = init_conf_app();
    if (SLS_OK != ret) {
        sls_log(SLS_LOG_ERROR, "[%p]CSLSListener::start, init_conf_app failed.", this);
        return SLS_ERROR;
    }

    //init listener
    if (NULL == m_srt)
        m_srt = new CSLSSrt();

    // Use different ports for publisher and player listeners
    sls_conf_server_t* server_conf = (sls_conf_server_t*)m_conf;
    if (m_is_publisher_listener) {
        m_port = server_conf->listen_publisher;
    } else {
        m_port = server_conf->listen_player;
    }
    
    if (m_port <= 0) {
        sls_log(SLS_LOG_ERROR, "[%p]CSLSListener::start, invalid port %d for %s listener.", 
                this, m_port, m_is_publisher_listener ? "publisher" : "player");
        return SLS_ERROR;
    }
    
    ret = m_srt->libsrt_setup(m_port);
    if (SLS_OK != ret) {
        sls_log(SLS_LOG_ERROR, "[%p]CSLSListener::start, libsrt_setup failure.", this);
        return ret;
    }
    sls_log(SLS_LOG_INFO, "[%p]CSLSListener::start, libsrt_setup ok on port %d for %s.", 
            this, m_port, m_is_publisher_listener ? "publisher" : "player");

    int latency = ((sls_conf_server_t*)m_conf)->latency;
    if (latency > 0) {
        ret = m_srt->libsrt_setsockopt(SRTO_LATENCY, "SRTO_LATENCY",  &latency, sizeof (latency));
        if (SLS_OK != ret) {
            sls_log(SLS_LOG_INFO, "[%p]CSLSListener::start, libsrt_setsockopt latency=%d failure.", this, latency);
            return ret;
        }
    }

    ret = m_srt->libsrt_listen(m_back_log);
    if (SLS_OK != ret) {
        sls_log(SLS_LOG_INFO, "[%p]CSLSListener::start, libsrt_listen failure.", this);
        return ret;
    }

    sls_log(SLS_LOG_INFO, "[%p]CSLSListener::start, m_list_role=%p.", this, m_list_role);
    if (NULL == m_list_role) {
        sls_log(SLS_LOG_INFO, "[%p]CSLSListener::start, m_roleList is null.", this);
        return ret;
    }


    sls_log(SLS_LOG_INFO, "[%p]CSLSListener::start, push to m_list_role=%p.", this, m_list_role);
    m_list_role->push(this);

	return ret;
}

int CSLSListener::stop()
{
	int ret = SLS_OK;
    sls_log(SLS_LOG_INFO, "[%p]CSLSListener::stop.", this);

 	return ret;
}

bool CSLSListener::validate_stream_id(const char* stream_id, char* mapped_id)
{
    StreamIdMapper& mapper = StreamIdMapper::getInstance();
    
    if (m_is_publisher_listener) {
        // For publisher, check if the stream ID is a valid publisher ID
        if (mapper.isValidPublisher(std::string(stream_id))) {
            return true;
        }
        sls_log(SLS_LOG_WARNING, "[%p]CSLSListener::validate_stream_id, invalid publisher stream ID='%s'", 
                this, stream_id);
        return false;
    } else {
        // For player, check if the stream ID is a valid player ID and get mapped publisher ID
        std::string publisher_id;
        if (mapper.isValidPlayer(std::string(stream_id), &publisher_id)) {
            if (mapped_id != nullptr) {
                strcpy(mapped_id, publisher_id.c_str());
            }
            return true;
        }
        sls_log(SLS_LOG_WARNING, "[%p]CSLSListener::validate_stream_id, invalid player stream ID='%s'", 
                this, stream_id);
        return false;
    }
}

int CSLSListener::handler()
{
	int ret = SLS_OK;
	int fd_client = 0;
	CSLSSrt *srt = NULL;
	char sid[1024] = {0};
	int  sid_size = sizeof(sid);
	char stream_name[URL_MAX_LEN] = {0};
    char tmp[URL_MAX_LEN] = {0};
    char peer_name[IP_MAX_LEN] = {0};
    int  peer_port = 0;
    int  client_count = 0;

    //1: accept
    fd_client = m_srt->libsrt_accept();
    if (ret < 0) {
        sls_log(SLS_LOG_ERROR, "[%p]CSLSListener::handler, srt_accept failed, fd=%d.", this, get_fd());
        CSLSSrt::libsrt_neterrno();
        return client_count;
    }
    client_count = 1;

    //2.check streamid, split it
	srt = new CSLSSrt;
	srt->libsrt_set_fd(fd_client);
    ret = srt->libsrt_getpeeraddr(peer_name, peer_port);
    if (ret != 0) {
        sls_log(SLS_LOG_ERROR, "[%p]CSLSListener::handler, libsrt_getpeeraddr failed, fd=%d.", this, srt->libsrt_get_fd());
        srt->libsrt_close();
        delete srt;
        return client_count;
    }
    sls_log(SLS_LOG_INFO, "[%p]CSLSListener::handler, new client[%s:%d], fd=%d.", this, peer_name, peer_port, fd_client);

    if (0 != srt->libsrt_getsockopt(SRTO_STREAMID, "SRTO_STREAMID", &sid, &sid_size)) {
        sls_log(SLS_LOG_ERROR, "[%p]CSLSListener::handler, [%s:%d], fd=%d, get streamid info failed.",
                this, peer_name, peer_port, srt->libsrt_get_fd());
    	srt->libsrt_close();
        delete srt;
    	return client_count;
    }
    
    if (strlen(sid) == 0) {
        sls_log(SLS_LOG_ERROR, "[%p]CSLSListener::handler, [%s:%d], empty stream ID not allowed.", 
                this, peer_name, peer_port);
        srt->libsrt_close();
        delete srt;
        return client_count;
    }
    
    // Port-based mode: stream ID is just the random value
    sls_conf_server_t* server_conf = (sls_conf_server_t*)m_conf;
    char mapped_stream_id[1024] = {0};
    
    // Validate stream ID
    if (!validate_stream_id(sid, mapped_stream_id)) {
        sls_log(SLS_LOG_ERROR, "[%p]CSLSListener::handler, [%s:%d], invalid stream ID='%s'.", 
                this, peer_name, peer_port, sid);
        srt->libsrt_close();
        delete srt;
        return client_count;
    }
    
    // For player listener, use mapped ID if provided
    if (!m_is_publisher_listener && strlen(mapped_stream_id) > 0) {
        strcpy(stream_name, mapped_stream_id);
    } else {
        strcpy(stream_name, sid);
    }
    
    sls_log(SLS_LOG_INFO, "[%p]CSLSListener::handler, [%s:%d], stream_name='%s'",
            this, peer_name, peer_port, stream_name);

    char key_stream_name[URL_MAX_LEN];
    strcpy(key_stream_name, stream_name);

    void * ca = NULL;

    char cur_time[STR_DATE_TIME_LEN] = {0};
    sls_gettime_default_string(cur_time);

    //3.is player?
    if (!m_is_publisher_listener) {
        // This is a player listener, handle as player
        CSLSRole * pub = m_map_publisher->get_publisher(key_stream_name);
        if (NULL == pub) {
        	//*
        	//3.1 check pullers
        	if (NULL == m_map_puller) {
    			sls_log(SLS_LOG_INFO, "[%p]CSLSListener::handler, refused, new role[%s:%d], stream='%s', publisher is NULL and m_map_puller is NULL.",
    						this, peer_name, peer_port, key_stream_name);
    			srt->libsrt_close();
    			delete srt;
    			return client_count;
        	}
        	CSLSRelayManager *puller_manager = m_map_puller->add_relay_manager(key_stream_name, stream_name);
        	if (NULL == puller_manager) {
    			sls_log(SLS_LOG_INFO, "[%p]CSLSListener::handler, m_map_puller->add_relay_manager failed, new role[%s:%d], stream='%s', publisher is NULL, no puller_manager.",
    						this, peer_name, peer_port, key_stream_name);
    			srt->libsrt_close();
    			delete srt;
    			return client_count;
        	}

        	puller_manager->set_map_data(m_map_data);
        	puller_manager->set_map_publisher(m_map_publisher);
        	puller_manager->set_role_list(m_list_role);
        	puller_manager->set_listen_port(m_port);

        	if (SLS_OK != puller_manager->start()) {
    			sls_log(SLS_LOG_INFO, "[%p]CSLSListener::handler, puller_manager->start failed, new client[%s:%d], stream='%s'.",
    						this, peer_name, peer_port, key_stream_name);
    			srt->libsrt_close();
    			delete srt;
    			return client_count;
            }
    	    sls_log(SLS_LOG_INFO, "[%p]CSLSListener::handler, puller_manager->start ok, new client[%s:%d], stream=%s.",
	            this, peer_name, peer_port, key_stream_name);

    	    pub = m_map_publisher->get_publisher(key_stream_name);
            if (NULL == pub) {
        	    sls_log(SLS_LOG_INFO, "[%p]CSLSListener::handler, m_map_publisher->get_publisher failed, new client[%s:%d], stream=%s.",
    	            this, peer_name, peer_port, key_stream_name);
    			srt->libsrt_close();
    			delete srt;
    			return client_count;
            } else {
        	    sls_log(SLS_LOG_INFO, "[%p]CSLSListener::handler, m_map_publisher->get_publisher ok, pub=%p, new client[%s:%d], stream=%s.",
    	            this, pub, peer_name, peer_port, key_stream_name);
            }
        }

        //3.2 handle new play
        if (!m_map_data->is_exist(key_stream_name)) {
            sls_log(SLS_LOG_ERROR, "[%p]CSLSListener::handler, refused, new role[%s:%d], stream=%s,but publisher data doesn't exist in m_map_data.",
                        this, peer_name, peer_port, key_stream_name);
            srt->libsrt_close();
            delete srt;
            return client_count;
        }

		//new player
		if (srt->libsrt_socket_nonblock(0) < 0)
			sls_log(SLS_LOG_WARNING, "[%p]CSLSListener::handler, new player[%s:%d], libsrt_socket_nonblock failed.",
					this, peer_name, peer_port);

		CSLSPlayer * player = new CSLSPlayer;
		player->init();
		player->set_idle_streams_timeout(m_idle_streams_timeout_role);
		player->set_srt(srt);
		player->set_map_data(key_stream_name, m_map_data);
		//stat info
	    sprintf(tmp, SLS_PLAYER_STAT_INFO_BASE,
	    		m_port, player->get_role_name(), stream_name, sid, peer_name, peer_port, cur_time);
	    std::string stat_info = std::string(tmp);
	    player->set_stat_info_base(stat_info);
	    player->set_http_url(m_http_url_role);
	    player->on_connect();

		m_list_role->push(player);
		sls_log(SLS_LOG_INFO, "[%p]CSLSListener::handler, new player[%p]=[%s:%d], key_stream_name=%s, %s=%p, m_list_role->size=%d.",
				this, player, peer_name, peer_port, key_stream_name, pub->get_role_name(), pub, m_list_role->size());
        return client_count;
    }

    //4. is publisher?
    // Publisher listener always handles as publisher
    if (m_is_publisher_listener) {
        // Direct use of stream name without domain/app prefix
        CSLSRole * publisher = m_map_publisher->get_publisher(key_stream_name);
        if (NULL != publisher) {
            sls_log(SLS_LOG_ERROR, "[%p]CSLSListener::handler, refused, new role[%s:%d], stream='%s',but publisher=%p is not NULL.",
                        this, peer_name, peer_port, key_stream_name, publisher);
            srt->libsrt_close();
            delete srt;
            return client_count;
        }
        
        //create new publisher
        CSLSPublisher * pub = new CSLSPublisher;
        pub->set_srt(srt);
        pub->set_conf(server_conf);
        pub->init();
        pub->set_idle_streams_timeout(m_idle_streams_timeout_role);
        //stat info
        sprintf(tmp, SLS_PUBLISHER_STAT_INFO_BASE,
                m_port, pub->get_role_name(), stream_name, sid, peer_name, peer_port, cur_time);
        std::string stat_info = std::string(tmp);
        pub->set_stat_info_base(stat_info);
        pub->set_http_url(m_http_url_role);
        //set hls record path
        sprintf(tmp, "%s/%d/%s",
                m_record_hls_path_prefix, m_port, key_stream_name);
        pub->set_record_hls_path(tmp);

        sls_log(SLS_LOG_INFO, "[%p]CSLSListener::handler, new pub=%p, key_stream_name=%s.",
                this, pub, key_stream_name);

        //init data array
        if (SLS_OK != m_map_data->add(key_stream_name)) {
            sls_log(SLS_LOG_WARNING, "[%p]CSLSListener::handler, m_map_data->add failed, new pub[%s:%d], stream=%s.",
                    this, peer_name, peer_port, key_stream_name);
            pub->uninit();
            delete pub;
            pub = NULL;
            return client_count;
        }

        if (SLS_OK != m_map_publisher->set_push_2_pushlisher(key_stream_name, pub)) {
            sls_log(SLS_LOG_WARNING, "[%p]CSLSListener::handler, m_map_publisher->set_push_2_pushlisher failed, key_stream_name=%s.",
                        this, key_stream_name);
            pub->uninit();
            delete pub;
            pub = NULL;
            return client_count;
        }
        pub->set_map_publisher(m_map_publisher);
        pub->set_map_data(key_stream_name, m_map_data);
        pub->on_connect();
        m_list_role->push(pub);
        sls_log(SLS_LOG_INFO, "[%p]CSLSListener::handler, new publisher[%s:%d], key_stream_name=%s.",
                this, peer_name, peer_port, key_stream_name);

        //5. check pusher
        if (NULL == m_map_pusher) {
            return client_count;
        }
        CSLSRelayManager *pusher_manager = m_map_pusher->add_relay_manager(key_stream_name, stream_name);
        if (NULL == pusher_manager) {
            sls_log(SLS_LOG_INFO, "[%p]CSLSListener::handler, m_map_pusher->add_relay_manager failed, new role[%s:%d], key_stream_name=%s.",
                        this, peer_name, peer_port, key_stream_name);
            return client_count;
        }
        pusher_manager->set_map_data(m_map_data);
        pusher_manager->set_map_publisher(m_map_publisher);
        pusher_manager->set_role_list(m_list_role);
        pusher_manager->set_listen_port(m_port);

        if (SLS_OK != pusher_manager->start()) {
            sls_log(SLS_LOG_INFO, "[%p]CSLSListener::handler, pusher_manager->start failed, new role[%s:%d], key_stream_name=%s.",
                        this, peer_name, peer_port, key_stream_name);
        }
    }
    
    return client_count;
}

std::string   CSLSListener::get_stat_info()
{
	if (m_stat_info.length() == 0) {
	    char tmp[STR_MAX_LEN] = {0};
	    char cur_time[STR_DATE_TIME_LEN] = {0};
	    sls_gettime_default_string(cur_time);
	    sprintf(tmp, SLS_SERVER_STAT_INFO_BASE, m_port, m_role_name, cur_time);
	    m_stat_info = std::string(tmp);
	}
	return m_stat_info;
}



