# SRT Dynamic Latency Configuration

This document describes the dynamic latency configuration feature in SRT-Live-Server.

## Overview

SRT-Live-Server supports dynamic latency configuration with the following behavior:
- **Publishers**: Can set their desired latency within configured min/max bounds
- **Players**: Cannot set minimum latency on listener, but maximum limit is enforced

## How It Works

### Publisher Side
1. Publishers can specify their desired latency when connecting
2. Minimum latency is enforced on the listener socket (cannot be bypassed)
3. Maximum latency is checked after connection (rejected if exceeded)

### Player Side
1. Players cannot set latency on the listener socket (no minimum enforcement)
2. The latency is determined by network conditions during negotiation
3. Maximum latency limit is enforced (connections exceeding it are rejected)

## Configuration Parameters

```
server {
    latency_min 200;    # Minimum latency for publishers only (0 = no enforcement)
    latency_max 5000;   # Maximum latency for all connections (0 = no enforcement)
}
```

- **latency_min**: Minimum latency enforced on publisher listener socket only
- **latency_max**: Maximum latency enforced for both publishers and players

## Important Notes

### Latency Enforcement Summary

| Connection Type | Minimum Enforcement | Maximum Enforcement |
|----------------|-------------------|-------------------|
| Publisher      | ✓ On listener socket | ✓ After connection |
| Player         | ✗ Not enforced | ✓ After connection |

### Why Different Enforcement?

- **Minimum for Publishers Only**: 
  - Ensures sufficient buffering for reliable upload
  - Publishers control the source quality
- **No Minimum for Players**: 
  - Allows flexible buffering based on network conditions
  - Low-latency monitoring and LAN connections possible
- **Maximum for Both**: 
  - Prevents excessive end-to-end latency
  - Controls memory usage and user experience

### End-to-End Latency

The total end-to-end latency is approximately:
```
Publisher Latency + Network Delay + Player Latency
```

By limiting the maximum for both, we prevent extreme delays while allowing flexibility for players.

## Client Examples

### FFmpeg (uses microseconds)
```bash
# Publisher with 1 second latency (1000ms = 1,000,000 microseconds)
ffmpeg -re -i input.mp4 -c copy -f mpegts "srt://server:4001?streamid=mystream&latency=1000000"

# Player - latency negotiated by network (can be lower than publisher)
ffplay "srt://server:4001?streamid=mystream&latency=150000"  # Can get 150ms if network allows
```

### OBS Studio (uses microseconds)
```
# Player URL
srt://server:4001?streamid=mystream&latency=1000000
```

## API Response

The `/stats` API endpoint shows the negotiated latency for each connection:

```json
{
  "publishers": {
    "live": {
      ...
      "latency": 1000,  // Publisher's negotiated latency in ms
      ...
    }
  }
}
```

## Troubleshooting

### Connection rejected due to latency
If a connection is rejected, check:
1. Publishers: Latency must be within both `latency_min` and `latency_max`
2. Players: Latency must be below `latency_max` only
3. For FFmpeg, ensure you're using microseconds (multiply milliseconds by 1000)

### Understanding Player Behavior
- Players can negotiate any latency up to `latency_max`
- They are not restricted by `latency_min`
- This allows for ultra-low latency monitoring or LAN playback 