# MySQL Connection Pool RTT Blind Spot

## Problem

The eBPF agent uses two mechanisms for latency measurement:

| Mechanism | Hook | What it measures | Blind spot |
|---|---|---|---|
| `tcp_sendmsg` kprobe/kretprobe | Kernel send path | Kernel buffer copy time (~µs) | Not real RTT |
| `tcp_conntrack` (tcp_close) | Connection close | Full connection lifetime | Pooled connections never close |

**Result**: For long-lived pooled connections (MySQL, Redis, PostgreSQL), neither mechanism captures request-level round-trip time. A MySQL query that takes 2000ms network RTT may appear as 0.05ms in the `tcp_sendmsg` trace.

### Why connection pooling breaks tcp_conntrack

```
Application                 MySQL
    |                         |
    |-- connect ------------->|  tcp_connect fires → conn_track entry created
    |<-- accept --------------|
    |                         |
    |-- query 1 (5ms) ------->|  No event emitted
    |<-- response ------------|
    |                         |
    |-- query 2 (2000ms) ---->|  No event emitted (slow query invisible!)
    |<-- response ------------|
    |                         |
    ... 10,000 more queries ...
    |                         |
    |   (connection stays open, never closes)
    |                         |
    |   tcp_close NEVER fires → duration NEVER measured
```

## Solution: `tcp_rtt.c` — Request-Level RTT

### Design

- **kprobe/tcp_sendmsg**: Records `{sk_ptr, send_ts_ns, pid, saddr, daddr, sport, dport}` in `rtt_track` hash map
- **kretprobe/tcp_recvmsg**: Looks up entry by `sk_ptr`, computes `delta_ns = now - send_ts_ns`, submits to `rtt_events` ringbuf
- **Keyed by `sk_ptr`** (socket pointer): Correctly pairs send/recv on the same TCP socket, even with concurrent requests
- **Sampling**: 100µs per-flow rate limit to avoid ringbuf overflow
- **Guard**: RTT > 30s is discarded (idle keep-alive, not a real request)

### Data flow

```
tcp_sendmsg(sk)                    tcp_recvmsg(sk) returns
    |                                    |
    v                                    v
rtt_track[sk_ptr] = {ts}          lookup rtt_track[sk_ptr]
                                  delta = now - ts
                                  if delta < 30s:
                                      submit net_event to rtt_events ringbuf
                                  delete rtt_track[sk_ptr]
                                         |
                                         v
                              Go: consumeRTTEvents() goroutine
                              reads ringbuf, parses netEventRaw,
                              calls graph.AddCall(src, dst, rttMs, isErr)
```

### Files

| File | Purpose |
|---|---|
| `bpf/tcp_rtt.c` | eBPF program (kprobe/kretprobe + maps) |
| `cmd/tracer/tcp_rtt_bpfel.go` | Generated Go bindings (little-endian) |
| `cmd/tracer/tcp_rtt_bpfeb.go` | Generated Go bindings (big-endian) |
| `cmd/tracer/app.go` | Load/attach in `Start()`, consume in `consumeRTTEvents()`, close in `Shutdown()` |

### Comparison with existing probes

| | `net_trace.c` (tracer) | `tcp_conntrack.c` | `tcp_rtt.c` (NEW) |
|---|---|---|---|
| Hook | kprobe/kretprobe tcp_sendmsg | kprobe tcp_connect + tcp_close | kprobe tcp_sendmsg + kretprobe tcp_recvmsg |
| Key | pid_tgid | sk_ptr | sk_ptr |
| Measures | Kernel sendmsg duration | Connection lifetime | Request-response RTT |
| Works for pooled conns | No (measures kernel time) | No (close never fires) | **Yes** |
| Output ringbuf | `events` | `conn_events` | `rtt_events` |
| Event struct | `net_event` | `conn_event` | `net_event` (reused) |

## Testing Process

### Prerequisites

- Running eBPF agent on target host (K3s node or local)
- Access to a service with connection pooling (MySQL, Redis)

### Step 1: Build and deploy

```bash
cd ebpfagent
go generate ./...
go build ./...
sudo ./ebpfagent &
```

### Step 2: Inject latency on target service

```bash
# On the machine where MySQL runs (or use tc netem on the pod's network namespace)
sudo tc qdisc add dev ens33 root netem delay 2000ms
```

### Step 3: Trigger traffic

```bash
# Run a query that goes through the pooled connection
mysql -h <target-ip> -e "SELECT SLEEP(0)"  # Simple query, should take ~2000ms due to tc
```

### Step 4: Observe RTT events

In the agent output, look for events from the `rtt_events` ringbuf:

```
CONN client 10.42.0.1:45678 -> 10.42.0.15:3306 duration=0.05 ms pid=1234 (mysql)
RTT  10.42.0.1:45678 -> 10.42.0.15:3306 rtt=2001.23 ms   # <-- This is the new signal
```

### Step 5: Verify via MCP

```bash
# Query the topology via MCP
curl -X POST http://localhost:50052/message -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"get_topology","arguments":{"include_healthy":true}},"id":1}'
```

Verify that:
1. RTT-based edges appear in the topology
2. Anomaly scores reflect real RTT, not kernel buffer time
3. P95 values for MySQL edges are close to real query latency

### Step 6: End-to-end anomaly test

```bash
# Start Python daemon
cd aetherops && python main.py &

# Inject 2000ms delay on MySQL
sudo tc qdisc add dev ens33 root netem delay 2000ms

# Observe:
# 1. eBPF detects high P95 on MySQL edge (from RTT events)
# 2. analyzeRootCause flags MySQL as suspect
# 3. MCP publishes anomaly notification
# 4. Python daemon receives notification
# 5. Multi-agent workflow runs
# 6. LLM diagnosis identifies MySQL as root cause
# 7. Remediation is evaluated/executed
```

### Step 7: Cleanup

```bash
# Remove tc netem delay
sudo tc qdisc del dev ens33 root

# Stop agents
kill <ebpfagent-pid>
kill <python-daemon-pid>
```

## Verification Checklist

- [ ] `tcp_rtt.c` compiles without errors (`clang -target bpf`)
- [ ] Go build succeeds (`go build ./...`)
- [ ] Agent starts and logs "tcp_rtt probes loaded"
- [ ] RTT events flow through ringbuf to `consumeRTTEvents()`
- [ ] `graph.AddCall()` receives RTT-based latency values (not kernel buffer time)
- [ ] MCP `get_topology` shows edges with RTT-derived P95
- [ ] Anomaly detection triggers on real RTT increase (not just tcp_sendmsg duration)
- [ ] Graceful degradation: if tcp_rtt probes fail to attach, agent still works with existing probes
