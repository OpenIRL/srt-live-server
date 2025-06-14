# SRT Live Server API Documentation

## Overview

The SRT Live Server now includes a secure REST API with authentication, rate limiting, and SQLite database storage. All API endpoints (except `/health` and `/stats`) require authentication using Bearer tokens.

## Authentication

All API requests must include an Authorization header:

```
Authorization: Bearer <API_KEY>
```

### Default Admin Key

When the server starts for the first time, it will generate a default admin API key and print it to the console:

```
Generated default admin API key: <32-character-key>
IMPORTANT: Save this key securely. It will not be shown again.
```

## API Endpoints

### Health Check

Check if the server is running.

```
GET /health
```

**Response:**
```json
{
  "status": "ok",
  "service": "srt-live-server",
  "version": "1.6.0"
}
```

### Stream IDs Management

#### List All Stream IDs

```
GET /api/stream-ids
Authorization: Bearer <API_KEY>
```

**Response:**
```json
{
  "status": "success",
  "data": [
    {
      "publisher": "studio_1",
      "player": "live_stream",
      "description": "Main studio feed"
    }
  ]
}
```

#### Add Stream ID

```
POST /api/stream-ids
Authorization: Bearer <API_KEY>
Content-Type: application/json

{
  "publisher": "studio_1",
  "player": "live_stream",
  "description": "Main studio feed (optional)"
}
```

**Required Permissions:** `admin` or `write`

**Response:**
- `200 OK` - Stream ID added successfully
  ```json
  {
    "status": "success",
    "message": "Stream ID added successfully"
  }
  ```
- `400 Bad Request` - Invalid request body or missing required fields
- `401 Unauthorized` - Invalid or missing API key
- `403 Forbidden` - Insufficient permissions
- `409 Conflict` - Stream ID with the given player ID already exists
  ```json
  {
    "status": "error",
    "message": "Stream ID with player 'demo' already exists"
  }
  ```

#### Delete Stream ID

```
DELETE /api/stream-ids/{player_id}
Authorization: Bearer <API_KEY>
```

**Required Permissions:** `admin`

**Response:**
```json
{
  "status": "success",
  "message": "Stream ID deleted successfully"
}
```

### Statistics

#### Get Publisher Statistics

Get real-time statistics for a specific publisher (using player ID).

**Note: This endpoint does not require authentication.**

**Endpoint:** `GET /stats/{player_id}`

**Parameters:**
- `player_id` (path) - The player ID associated with the publisher
- `reset` (query, optional) - Reset statistics after retrieval

**Response:**
```json
{
  "publishers": {
    "live": {
      "bitrate": 16363,
      "bytes_rcv_drop": 0,
      "bytes_rcv_loss": 0,
      "mbps_bandwidth": 2.1,
      "mbps_recv_rate": 2.4,
      "ms_rcv_buf": 1984,
      "pkt_rcv_drop": 0,
      "pkt_rcv_loss": 0,
      "rtt": 30.2,
      "uptime": 3600,
      "latency": 2000
    }
  },
  "status": "ok"
}
```

### Configuration

#### Get Server Configuration

```
GET /api/config
Authorization: Bearer <API_KEY>
```

**Response:**
```json
{
  "status": "success",
  "data": {
    "listen_publisher": 4001,
    "listen_player": 4000,
    "http_port": 8080,
    "latency": 2000
  }
}
```

### API Key Management

#### Create New API Key

```
POST /api/keys
Authorization: Bearer <API_KEY>
Content-Type: application/json

{
  "name": "Frontend App",
  "permissions": "read"
}
```

**Required Permissions:** `admin`

**Permission Levels:**
- `admin`: Full access to all endpoints
- `write`: Can read and write stream IDs
- `read`: Read-only access

**Response:**
```json
{
  "status": "success",
  "api_key": "<new-32-character-key>",
  "message": "Save this key securely. It cannot be retrieved again."
}
```

## Rate Limiting

The API implements rate limiting to prevent abuse. Each endpoint type has its own separate rate limit:

- **API endpoints** (`api`): 30 requests per minute per IP (configurable via `rate_limit_api`)
  - GET /api/stream-ids
  - POST /api/stream-ids
  - DELETE /api/stream-ids/{player_id}
- **Statistics** (`stats`): 300 requests per minute per IP (configurable via `rate_limit_stats`)
  - GET /stats/{player_id}
- **Configuration** (`config`): 20 requests per minute per IP (configurable via `rate_limit_config`)
  - GET /api/config
  - POST /api/keys

Each endpoint type is tracked separately, so high usage of statistics endpoints won't affect your ability to use other API endpoints.

### Configuration

Rate limits can be configured in `sls.conf`:

```
srt {
    # Rate limiting configuration (requests per minute)
    rate_limit_api 30;      # For API endpoints (stream IDs)
    rate_limit_stats 300;   # For statistics endpoints
    rate_limit_config 20;   # For configuration endpoints (config, API keys)
}
```

When rate limit is exceeded:
```json
{
  "status": "error",
  "message": "Rate limit exceeded"
}
```

## Error Responses

### 401 Unauthorized
```json
{
  "status": "error",
  "message": "Missing or invalid Authorization header"
}
```

### 403 Forbidden
```json
{
  "status": "error",
  "message": "Insufficient permissions"
}
```

### 404 Not Found
```json
{
  "status": "error",
  "message": "Stream ID not found"
}
```

### 429 Too Many Requests
```json
{
  "status": "error",
  "message": "Rate limit exceeded"
}
```

## Database Schema

The SQLite database (`/etc/sls/streams.db`) contains:

### stream_ids table
- `id`: Primary key
- `publisher`: Publisher stream ID
- `player`: Player stream ID (unique)
- `description`: Optional description
- `created_at`: Creation timestamp
- `updated_at`: Last update timestamp

### api_keys table
- `id`: Primary key
- `key_hash`: SHA256 hash of API key
- `name`: Key name/description
- `permissions`: Permission level (admin/write/read)
- `created_at`: Creation timestamp
- `last_used`: Last usage timestamp
- `active`: Boolean status

### access_logs table
- `id`: Primary key
- `api_key_id`: Foreign key to api_keys
- `endpoint`: API endpoint accessed
- `method`: HTTP method
- `ip_address`: Client IP
- `timestamp`: Access timestamp
- `response_code`: HTTP response code

## Usage Examples

### Bash/cURL

```bash
# Get all stream IDs
curl -H "Authorization: Bearer YOUR_API_KEY" \
  http://hostname:8080/api/stream-ids

# Add new stream ID
curl -X POST -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"publisher":"studio_1","player":"live_stream"}' \
  http://hostname:8080/api/stream-ids

# Get statistics
curl -H "Authorization: Bearer YOUR_API_KEY" \
  http://hostname:8080/stats/live_stream
```

### Python

```python
import requests

API_KEY = "your_api_key_here"
BASE_URL = "http://hostname:8080"

headers = {"Authorization": f"Bearer {API_KEY}"}

# List stream IDs
response = requests.get(f"{BASE_URL}/api/stream-ids", headers=headers)
stream_ids = response.json()

# Add new stream ID
data = {
    "publisher": "studio_1",
    "player": "live_stream",
    "description": "Main studio feed"
}
response = requests.post(f"{BASE_URL}/api/stream-ids", json=data, headers=headers)
```

### JavaScript/Fetch

```javascript
const API_KEY = 'your_api_key_here';
const BASE_URL = 'http://hostname:8080';

// List stream IDs
fetch(`${BASE_URL}/api/stream-ids`, {
    headers: {
        'Authorization': `Bearer ${API_KEY}`
    }
})
.then(response => response.json())
.then(data => console.log(data));

// Add new stream ID
fetch(`${BASE_URL}/api/stream-ids`, {
    method: 'POST',
    headers: {
        'Authorization': `Bearer ${API_KEY}`,
        'Content-Type': 'application/json'
    },
    body: JSON.stringify({
        publisher: 'studio_1',
        player: 'live_stream',
        description: 'Main studio feed'
    })
})
.then(response => response.json())
.then(data => console.log(data));
```

## Security Considerations

1. **API Keys**: Store API keys securely. Never commit them to version control.
2. **HTTPS**: In production, use HTTPS to protect API keys in transit.
3. **Network Security**: Restrict API access to trusted networks.
4. **Database Backup**: Regularly backup the SQLite database.
5. **Log Monitoring**: Monitor access_logs for suspicious activity.
