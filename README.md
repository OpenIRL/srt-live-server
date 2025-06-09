Introduction
============

srt-live-server(SLS) is an open source live streaming server for low latency based on Secure Reliable Tranport(SRT).
Normally, the latency of transport by SLS is less than 1 second in internet.


Requirements
============

please install the SRT first, refer to SRT(https://github.com/Haivision/srt) for system enviroment.
SLS can only run on OS based on linux, such as mac, centos or ubuntu etc.

Compile
=======

$ sudo make

bin file is generated in subdir of 'bin'.

Directivies
===========

about the config file, please see the wiki:
https://github.com/Edward-Wu/srt-live-server/wiki/Directives

Usage
=====

$ cd bin

1.help information
------------------
$ ./sls -h

2.run with default config file
------------------------------
$ ./sls -c ../sls.conf

Test
====

SLS only supports the MPEG-TS format streaming. 

1.test with ffmpeg
------------------

you can push camera live stream by FFMPEG.Please download ffmpeg sourcecode from https://github.com/FFmpeg/FFmpeg, then compile FFMPEG with --enable-libsrt. 

srt library is installed in folder /usr/local/lib64.
if "ERROR: srt >= 1.3.0 not found using pkg-config" occured when compiling FFMPEG, please check the ffbuild/config.log file and follow its instruction to resolve this issue. in most cases it can be resolved by the following command:
export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig:/usr/local/lib64/pkgconfig

if "error while loading shared libraries: libsrt.so.1" occured, please add srt library path to file '/etc/ld.so.conf' as the default path, then refresh by comand /sbin/ldconfig with root.


use ffmpeg to push camera stream with SRT(on my mac):

./ffmpeg -re -f avfoundation -i "0:0" -vcodec libx264 -acodec libmp3lame -ar 44100 -ac 1 -f mpegts "srt://[your.sls.ip]:4001?streamid=publisher_id"


2.how to play
-------------

play the SRT stream with ffplay:

./ffplay -fflags nobuffer -i "srt://[your.sls.ip]:4000?streamid=player_id"


2.test with OBS
---------------

the OBS supports srt protocol to publish stream when version is later than v25.0. you can use the following url:
srt://[your.sls.ip]:4001?streamid=publisher_id
with custom service.

3.test with srt-live-client
---------------------------

there is a test tool in sls, which can be used performance test because of no codec overhead but main network overhead. the slc can play a srt stream to a ts file, or push a ts file to a srt stream.

push ts file as srt url:

cd bin

./slc -r srt://[your.sls.ip]:4001?streamid=publisher_id -i [the full file name of exist ts file]

play srt url

./slc -r srt://[your.sls.ip]:4000?streamid=player_id -o [the full file name of ts file to save]


Note:
=====

1. SLS uses simple stream IDs without domain/app prefixes. Stream IDs are validated against the streamids.json configuration file.

2. Publisher and player connections are distinguished by separate ports (listen_publisher and listen_player).

3.I supply a simple android app for test sls, your can download from https://github.com/Edward-Wu/liteplayer-srt

New Features (v1.5)
===================

Port-based Publisher/Player Separation (Required)
-------------------------------------------------

The server now requires separate ports for publishers and players, using simple stream IDs:

**Configuration:**
```
server {
    listen_publisher 4001;  # Port for publishers (required)
    listen_player 4000;     # Port for players (required)
    
    # Other configurations...
}
```

**URLs:**
- Publisher: `srt://server:4001?streamid=stream_id`
- Player: `srt://server:4000?streamid=stream_id`

Stream IDs are now simple values without domain/app prefixes.

Stream ID Mapping (Required)
----------------------------

For enhanced security, different stream IDs must be used for publishers and players. This is configured using a JSON file (`streamids.json`):

```json
[
    {
        "publisher": "6a204bd89f3c8348afd5c77c717a097a",
        "player": "422c6f92cd3b84b65e3cb90fab6544f5"
    },
    {
        "publisher": "1de6ce178679f16b48abc7d8a291cb2e",
        "player": "ed8cae86454f037bbcb0856cf1c2f0e3"
    }
]
```

With this configuration:
- Publishers must use their specific publisher ID
- Players use their player ID, which is automatically mapped to the publisher ID
- Only configured stream IDs are allowed
- The JSON file must exist and contain valid mappings

Statistics API Enhancement
--------------------------

The `/stats/` endpoint accepts only player IDs for security reasons:

```
GET http://server:8080/stats/422c6f92cd3b84b65e3cb90fab6544f5  # Using player ID
```

The player ID is automatically mapped to the corresponding publisher for statistics retrieval.

Configuration Requirements
--------------------------

The minimal configuration format:

```
server {
    listen_publisher 4001;  # Required
    listen_player 4000;     # Required
    
    latency 2000;
    backlog 100;
    idle_streams_timeout 3;
    
    publisher_exit_delay 10;
    record_hls off;
    record_hls_segment_duration 10;
}
```

**Breaking Changes:**
- Domain and app configurations have been removed
- Single-port configuration is no longer supported
- Stream IDs are now simple values without prefixes
- Default stream ID configuration has been removed
- Statistics are only accessible via player keys

ReleaseNote
============

v1.5
----
1. Port-based publisher/player separation with separate listen_publisher and listen_player ports
2. Simplified stream ID format without domain/app prefixes
3. Stream ID mapping with JSON-based security validation
4. Statistics API accessible only via player keys for enhanced security
5. Removed legacy configuration options (domain, app directives)

v1.4
----
1. support timestamp synchronization of players, resolve the timestamp rollover issue.
2. add on_event_url http callback, you can do some work when publisher/player connect/disconnect.
3. add push and pull features, support all and hash mode for push, support loop and hash for pull. in cluster mode, you can push a stream to a hash node, and pull this stream from the same hash node.

v1.3
----
1. support hostname:port/app in upstreams of pull and push.
2. support hostname/port/app in upstreams of pull and push.
3. hostname/port/app for upstreams becomes hostname:port/app.
4. support multiple apps in the same worker, improved the reliability.
5. add idle_streams_timeout feature for relay.

v1.2
----
1. update the memory mode, in v1.1 which is publisher copy data to eacc player, in v1.2 each publisher put data to a array and all players read data from this array.
2. update the relation of the publisher and player, the player is not a member of publisher. the only relation of them is array data.

v1.1
----
1. support reload configuration file, send SIGUSR1 to sls or call http interface.
2. support listen multiple ports.
3. add on_publisher_timeout and on_timeout_publisher for publisher.
4. add player.on_close_player for player.
5. OBS streaming compatible, OBS support the srt protocol which is later than v25.0.

v1.0
----
1. add hls output, if you want to save data to hls, config the record_hls,record_hls_segment_duration parameters. sls open the hls option, and hls can be play with Safari directly.
