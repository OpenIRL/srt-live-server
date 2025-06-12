# SRT Live Server

## Overview

SRT Live Server (sls) is a low latency streaming server that is using SRT (Secure Reliable Transport). This fork includes a secure REST API with authentication, SQLite database storage, and rate limiting for production use.

## Features

- **SRT Protocol Support**: Low latency streaming with SRT
- **Secure REST API**: Authentication with API keys and rate limiting
- **SQLite Database**: Persistent storage for stream IDs and configuration
- **Access Logging**: Complete audit trail of API usage
- **Docker Support**: Easy deployment with docker-compose
- **Auto-reload**: Configuration reload without service interruption

## Quick Start with Docker

1. Clone the repository:
```bash
git clone https://github.com/OpenIRL/srt-live-server.git
cd srt-live-server
```

2. Start with docker-compose:
```bash
docker-compose up -d
```

3. Check the logs for the admin API key:
```bash
docker-compose logs | grep "admin API key"
```

You'll see something like:
```
Generated default admin API key: AbCdEfGhIjKlMnOpQrStUvWxYz123456
IMPORTANT: Save this key securely. It will not be shown again.
```

4. Test video feed:

ffmpeg -re -f lavfi -i testsrc2=size=640x360:rate=25 -f lavfi -i sine=frequency=1000:sample_rate=48000 -c:v libx264 -preset ultrafast -tune zerolatency -c:a aac -f mpegts "srt://[your.sls.ip]:4001?streamid=publisher_id"

Receive it with OBS or VLC: srt://[your.sls.ip]:4000?streamid=player_id

## Configuration

### Ports

- `4000/udp`: Publisher port (SRT input)
- `4001/udp`: Player port (SRT output)
- `8080/tcp`: HTTP API port

### Configuration File

Edit `sls.conf` for advanced settings:

```conf
srt {
    worker_threads  1;
    worker_connections 300;
    
    http_port 8080;
    cors_header *;
    
    log_file logs/sls.log;
    log_level info;
    
    record_hls_path_prefix /tmp/sls/hls/;
    
    server {
        listen 4001;
        type player;
        
        latency 20;
        domain_player live.sls.com live.test.com;
        
        default_sid live/livestream;
        
        http_hook http://127.0.0.1:8080/on_event;
        on_event_url http://127.0.0.1:8080/on_event;
    }
    
server {
        listen 4000;
        type publisher;
        
        latency 20;
        domain_publisher uplive.sls.com;
        
        default_sid live/livestream;
        
        http_hook http://127.0.0.1:8080/on_event;
        on_event_url http://127.0.0.1:8080/on_event;
    }
}
```

## API Usage

See [API.md](API.md) for complete API documentation.

### Quick Examples

1. **Add a stream mapping**:
```bash
curl -X POST -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"publisher":"studio","player":"live"}' \
  http://host:8080/api/stream-ids
```

2. **List all streams**:
```bash
curl -H "Authorization: Bearer YOUR_API_KEY" \
  http://host:8080/api/stream-ids
```

3. **Get stream statistics**:
```bash
curl http://host:8080/stats/live
```

## Streaming URLs

### Publisher (Input)
```
srt://hostname:4001?streamid=publisher_id
```

### Player (Output)
```
srt://hostname:4000?streamid=player_id
```

## Building from Source

### Requirements

- Alpine Linux 3.20 or compatible
- CMake 3.0+
- GCC 7.0+
- OpenSSL development libraries
- SQLite3 development libraries

### Build Steps

```bash
# Install dependencies
apk add --no-cache linux-headers alpine-sdk cmake tcl openssl-dev sqlite-dev

# Build SRT library
git clone https://github.com/onsmith/srt.git
cd srt && ./configure && make && make install

# Build SRT Live Server
make
```

## Security Considerations

1. **Change Default API Key**: The default admin key should be changed immediately
2. **Use HTTPS**: In production, use a reverse proxy with SSL/TLS
3. **Network Security**: Restrict API access to trusted networks
4. **Regular Backups**: Backup the SQLite database regularly
5. **Monitor Logs**: Check access logs for suspicious activity

## Support

For issues and feature requests, please use the GitHub issue tracker.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
