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
#include "spdlog/spdlog.h"

#include "CxxUrl.hpp"
#include "SLSRelay.hpp"
#include "SLSLog.hpp"
#include "SLSRelayManager.hpp"
#include "util.hpp"

#define DEFAULT_LATENCY 100

/**
 * relay conf
 */
SLS_CONF_DYNAMIC_IMPLEMENT(relay)

/**
 * CSLSRelay class implementation
 */

CSLSRelay::CSLSRelay()
{
    m_is_write = 0;
    memset(m_url, 0, URL_MAX_LEN);
    memset(m_server_ip, 0, IP_MAX_LEN);

    m_server_port = 0;
    m_map_publisher = NULL;
    m_relay_manager = NULL;
    m_need_reconnect = true;

    sprintf(m_role_name, "relay");
}

CSLSRelay::~CSLSRelay()
{
    // release
}

int CSLSRelay::uninit()
{
    // for reconnect
    if (NULL != m_relay_manager)
    {
        ((CSLSRelayManager *)m_relay_manager)->add_reconnect_stream(m_url);
        spdlog::info("[{}] CSLSRelay::uninit, add_reconnect_stream, m_url={}.",
                     fmt::ptr(this), m_url);
    }

    return CSLSRole::uninit();
}

void CSLSRelay::set_map_publisher(CSLSMapPublisher *map_publisher)
{
    m_map_publisher = map_publisher;
}

void CSLSRelay::set_relay_manager(void *relay_manager)
{
    m_relay_manager = relay_manager;
}

void *CSLSRelay::get_relay_manager()
{
    return m_relay_manager;
}

int CSLSRelay::parse_url(char *url, char *host_name, size_t host_name_size, int &port, char *streamid, size_t streamid_size, int &latency)
{
    // Parse the URL
    Url parsed_url(url);
    string scheme;
    bool streamid_found = false;
    bool latency_found = false;
    try
    {
        // Check if URL scheme is correct
        scheme = parsed_url.scheme();
        if (scheme.compare("srt") != 0)
        {
            spdlog::error("[{}] CSLSRelay::parse_url invalid URL scheme [scheme='{}']", fmt::ptr(this), scheme);
            return SLS_ERROR;
        }
        // Copy hostname
        strlcpy(host_name, parsed_url.host().c_str(), host_name_size);
        // Set port
        port = stoi(parsed_url.port());

        // Get endpoint directly from path
        std::string path = parsed_url.path();
        if (!path.empty() && path[0] == '/') {
            path = path.substr(1);  // Remove leading slash
        }
        
        // Check if endpoint is valid
        if (!CSLSManager::get_instance()->get_endpoint_manager()->is_valid_ingest(path)) {
            spdlog::error("[{}] CSLSRelay::parse_url invalid endpoint '{}'", fmt::ptr(this), path);
            return SLS_ERROR;
        }

        // Set streamid to the endpoint
        strlcpy(streamid, path.c_str(), streamid_size);
        streamid_found = true;

        // Parse other query parameters
        for (Url::KeyVal query_param : parsed_url.query())
        {
            if (query_param.key().compare("latency") == 0)
            {
                try
                {
                    latency = stoi(query_param.val());
                    latency_found = true;
                }
                catch (std::overflow_error const &)
                {
                    spdlog::error("[{}] CSLSRelay::parse_url invalid latency [latency='{}']", fmt::ptr(this), query_param.val());
                    return SLS_ERROR;
                }
            }
        }
    }
    catch (Url::parse_error const &error)
    {
        spdlog::error("[{}] CSLSRelay::parse_url error [{}]", fmt::ptr(this), error.what());
        spdlog::error("[{}] CSLSRelay::parse_url URL should be in format 'srt://hostname:port/endpoint'", fmt::ptr(this));
        return SLS_ERROR;
    }

    if (!streamid_found)
    {
        spdlog::error("[{}] CSLSRelay::parse_url no endpoint found in URL '{}'", fmt::ptr(this), url);
        spdlog::error("[{}] CSLSRelay::parse_url URL should be in format 'srt://hostname:port/endpoint'", fmt::ptr(this));
        return SLS_ERROR;
    }

    if (!latency_found)
    {
        spdlog::warn("[{}] CSLSRelay::parse_url query parameter 'latency' not found in URL '{}', use default latency {}", 
                     fmt::ptr(this), url, DEFAULT_LATENCY);
    }

    return SLS_OK;
}

int CSLSRelay::open(const char *srt_url)
{
    const int bool_false = 0; // No compound literals in C++, sadly

    int ret;
    char host_name[HOST_MAX_LEN] = {};
    char server_ip[IP_MAX_LEN] = {};
    int server_port = 0;
    char streamid[URL_MAX_LEN] = {};
    char url[URL_MAX_LEN] = {};
    int latency;

    if (strnlen(srt_url, URL_MAX_LEN) >= URL_MAX_LEN)
    {
        spdlog::error("[{}] CSLSRelay::open invalid URL [url='{}']", fmt::ptr(this), srt_url);
        return SLS_ERROR;
    }
    strncpy(m_url, srt_url, sizeof(m_url) - 1);
    strncpy(url, srt_url, sizeof(url) - 1);

    // init listener
    if (NULL != m_srt)
    {
        spdlog::error("[{}] CSLSRelay::open, failure, url='{}', m_srt = {}, not NULL.", fmt::ptr(this), url, fmt::ptr(m_srt));
        return SLS_ERROR;
    }

    // parse url
    if (SLS_OK != parse_url(url, host_name, sizeof(host_name), server_port, streamid, sizeof(streamid), latency))
    {
        return SLS_ERROR;
    }
    spdlog::info("[{}] CSLSRelay::open, parse_url ok, url='{}'.", fmt::ptr(this), m_url);

    if ((ret = strnlen(streamid, URL_MAX_LEN)) == 0)
    {
        spdlog::error("[{}] CSLSRelay::open, url='{}', no 'stream', url must be like 'hostname:port?streamid=your_stream_id'.", fmt::ptr(this), m_url);
        return SLS_ERROR;
    }
    else if (ret >= URL_MAX_LEN)
    {
        spdlog::error("[{}] CSLSRelay::open, url='{}', 'stream' too long.", fmt::ptr(this), m_url);
        return SLS_ERROR;
    }

    SRTSOCKET fd = srt_create_socket();

    int status = srt_setsockopt(fd, 0, SRTO_LATENCY, &latency, sizeof(latency)); // set the latency
    if (status == SRT_ERROR)
    {
        spdlog::error("[{}] CSLSRelay::open, srt_setsockopt SRTO_LATENCY failure. err={}.", fmt::ptr(this), srt_getlasterror_str());
        return SLS_ERROR;
    }

    status = srt_setsockopt(fd, 0, SRTO_SNDSYN, &bool_false, sizeof(bool_false)); // for async write
    if (status == SRT_ERROR)
    {
        spdlog::error("[{}] CSLSRelay::open, srt_setsockopt SRTO_SNDSYN failure. err={}.", fmt::ptr(this), srt_getlasterror_str());
        return SLS_ERROR;
    }

    status = srt_setsockopt(fd, 0, SRTO_RCVSYN, &bool_false, sizeof(bool_false)); // for async read
    if (status == SRT_ERROR)
    {
        spdlog::error("[{}] CSLSRelay::open, srt_setsockopt SRTO_SNDSYN failure. err={}.", fmt::ptr(this), srt_getlasterror_str());
        return SLS_ERROR;
    }

    int lossmaxttlvalue = 40;
    srt_setsockopt(fd, 0, SRTO_LOSSMAXTTL, &lossmaxttlvalue, sizeof (lossmaxttlvalue));

    // srt_setsockflag(fd, SRTO_SENDER, &m_is_write, sizeof m_is_write);
    /*
    status = srt_setsockopt(fd, 0, SRTO_TSBPDMODE, &yes, sizeof yes); //
    if (status == SRT_ERROR) {
        sls_log(SLS_LOG_ERROR, "[%p]CSLSRelay::open, srt_setsockopt SRTO_TSBPDMODE failure. err=%s.", this, srt_getlasterror_str());
        return SLS_ERROR;
    }
    */
    /*
    SRT_TRANSTYPE tt = SRTT_LIVE;
    status = srt_setsockopt(fd, 0, SRTO_TRANSTYPE, &tt, sizeof tt);
    if (status == SRT_ERROR) {
        sls_log(SLS_LOG_ERROR, "[%p]CSLSRelay::open, srt_setsockopt SRTO_TRANSTYPE failure. err=%s.", this, srt_getlasterror_str());
        return SLS_ERROR;
    }
    */

    if (srt_setsockopt(fd, 0, SRTO_STREAMID, streamid, strlen(streamid)) < 0)
    {
        spdlog::error("[{}] CSLSRelay::open, srt_setsockopt SRTO_STREAMID failure. err={}.", fmt::ptr(this), srt_getlasterror_str());
        return SLS_ERROR;
    }

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_port = htons(server_port);

    sls_gethostbyname(host_name, server_ip);
    if (inet_pton(AF_INET, server_ip, &sa.sin_addr) != 1)
    {
        spdlog::error("[{}] CSLSRelay::open, inet_pton failure. server_ip={}, server_port={:d}.", fmt::ptr(this), server_ip, server_port);
        return SLS_ERROR;
    }

    struct sockaddr *psa = (struct sockaddr *)&sa;
    status = srt_connect(fd, psa, sizeof sa);
    if (status == SRT_ERROR)
    {
        spdlog::error("[{}] CSLSRelay::open, srt_connect failure. server_ip={}, server_port={:d}.", fmt::ptr(this), server_ip, server_port);
        return SLS_ERROR;
    }
    m_srt = new CSLSSrt();
    m_srt->libsrt_set_fd(fd);
    strlcpy(m_server_ip, server_ip, sizeof(m_server_ip));
    m_server_port = server_port;
    return status;
}

int CSLSRelay::close()
{
    int ret = SLS_OK;
    if (m_srt)
    {
        spdlog::info("[{}] CSLSRelay::close, ok, url='{}'.", fmt::ptr(this), m_url);
        ret = m_srt->libsrt_close();
        delete m_srt;
        m_srt = NULL;
    }
    return ret;
}

char *CSLSRelay::get_url()
{
    return m_url;
}

int CSLSRelay::get_peer_info(char *peer_name, int &peer_port)
{
    strcpy(peer_name, m_server_ip);
    peer_port = m_server_port;
    return SLS_OK;
}

int CSLSRelay::get_stat_base(char *stat_base)
{
    return SLS_OK;
}
