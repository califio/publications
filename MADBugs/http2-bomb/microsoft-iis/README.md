# IIS Denial of Service via HTTP/2 HPACK Decompression Amplification

## 1. Vulnerability

IIS accepts HTTP/2 requests containing up to 900 HPACK-compressed headers per stream, where each header is a 1-byte indexed reference that decompresses into a full header entry. With 100 streams per connection, each connection consumes kernel pool memory for decoded headers, request buffers, connection state, and response buffering. By setting `INITIAL_WINDOW_SIZE=0` in the HTTP/2 handshake, the attacker prevents IIS from delivering the response, keeping these allocations alive. A periodic 1-byte `WINDOW_UPDATE` drip resets the server's send timeout, holding the memory indefinitely.

With 50,000 concurrent connections (100 streams each), a single attacker exhausts 94.5% of a 96 GB server's memory in 45 seconds, rendering IIS unresponsive for over 100 seconds. The server leaks 12-16 GB of kernel pool memory that is not reclaimed after the attack, requiring a reboot for full recovery.

| | 64 GB server | 96 GB server |
|---|---|---|
| Peak memory | 99.7% | 94.5% |
| Time to outage | 15 seconds | 15 seconds |
| Outage duration | 105 seconds | 115 seconds |
| Residual kernel leak | 12.2 GB | 16 GB |
| Amplification | ~68:1 (wire -> memory) | ~68:1 |

## 2. Root Cause

When http.sys receives a HEADERS frame, `HkDecode` decompresses the HPACK payload and allocates kernel pool buffers for each decoded header pair. The decompressed request is processed through `UxDuoProcessCompleteCatalog` -> `UxDuoRunStreamReceivePump` -> `UlHttpReceiveHeadersEvent`, which allocates a request buffer and dispatches the request for response generation.

With `INITIAL_WINDOW_SIZE=0`, the response cannot be sent. The per-stream allocations (request buffer, connection state, response data) remain in kernel pool for the lifetime of the stream. The attacker extends this lifetime indefinitely by sending `WINDOW_UPDATE(increment=1)` every 5 seconds - `UxDuoUpdateStreamSendWindow` accepts any positive increment without minimum enforcement, and the resulting 1-byte send resets `Timer_MinBytesPerSecond` via `UxDuoDispatchWindowParcel`.

There is no per-connection or global memory budget for HTTP/2 request processing in http.sys. The existing defenses are insufficient:

- **DecompressionOverflow** (threshold ~921 headers) - bypassed by sending 900 headers per stream
- **Timer_MinBytesPerSecond** (~15s timeout) - bypassed by the 1-byte WINDOW_UPDATE drip
- **WINDOW_UPDATE rate limiter** - disabled by default (`Http2MaxWindowUpdatesPerSend = 0`)
- **All other per-frame DoS rate limiters** - disabled by default (registry defaults are 0)
- **MAX_CONCURRENT_STREAMS = 100** - bypassed by opening 10,000-50,000 connections
- **Connection backlog limit** - checks send backlog, not total memory consumption

## 3. Reproduction

### Setup

- **Target:** Windows Server 2025 Build 26100.32860 (http.sys 10.0.26100.32684), IIS with HTTPS on port 443 (default configuration)
- **Attacker:** Windows machine with Python 3 on the same network
- **Observer:** Any machine with `curl` on the same network

### Run

```powershell
# From the attacker - 64 GB target:
.\launch_attack.ps1 -Target <IP> -Preset 64gb

# From the attacker - 96 GB target:
.\launch_attack.ps1 -Target <IP> -Preset 96gb
```

```bash
# From the observer - probe during attack:
while true; do curl -sk --http2 --max-time 3 -o /dev/null -w "%{response_code}\n" https://<IP>/; sleep 3; done
```

### Expected: 64 GB Target

```
Memory:                            Observer:
  t+15s  10,889 MB  (16.6%)         t+10s  200
  t+20s  18,968 MB  (28.9%)         t+15s  DOWN  <- server unreachable
  t+45s  41,982 MB  (64.1%)         t+45s  DOWN
  t+75s  63,361 MB  (96.7%)         t+80s  DOWN
  t+95s  65,319 MB  (99.7%)  <- peak
  t+130s 15,798 MB  (24.1%)        t+130s  200   <- recovered
```

### Expected: 96 GB Target

```
Memory:                            Observer:
  t+5s   77,498 MB  (78.8%)         t+10s  200
  t+15s  83,522 MB  (85%)           t+15s  DOWN  <- server unreachable
  t+35s  90,426 MB  (92%)           t+45s  DOWN
  t+45s  92,920 MB  (94.5%)  <- peak
  t+90s  27,960 MB  (28.4%)         t+110s 200   <- recovered
```
