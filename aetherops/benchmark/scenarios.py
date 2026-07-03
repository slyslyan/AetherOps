# AetherOps — Incident Benchmark: 30 labeled fault scenarios
#
# Each scenario includes:
#   - event: the anomaly event (what the agent sees)
#   - topology: the service graph at the time
#   - ground_truth: node_id that is the real root cause
#   - expected_action: what remediation should be taken
#   - pattern: which of the 5 fault patterns it matches

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

import time


@dataclass
class BenchmarkScenario:
    name: str
    description: str
    anomaly_event: Dict
    topology: Dict
    ground_truth_root_cause: str
    expected_action: str
    pattern: str  # slow_query | cache_avalanche | network_congestion | resource_exhaustion | hot_spot
    expected_confidence_min: float = 0.0
    tags: List[str] = field(default_factory=list)
    metrics_mock: Optional[Dict] = None  # mock prometheus data for this scenario


# ── 30 Scenarios ──

SCENARIOS: List[BenchmarkScenario] = [
    # ── Pattern 1: Database Slow Query (6 scenarios) ──
    BenchmarkScenario(
        name="mysql-connection-pool-exhaustion",
        description="MySQL connection pool exhausted, backend connections queue up, latency spikes",
        anomaly_event={
            "node_id": "judgex-backend:8080",
            "anomaly_score": 72.5,
            "avg_latency_ms": 3200.0,
            "call_count": 280,
            "suspect_chain": ["mysql-0:3306", "redis:6379", "judgex-backend:8080"],
            "timestamp_unix_nano": int(time.time() * 1e9),
        },
        topology={
            "nodes": [
                {"id": "nginx", "avg_latency_ms": 5.0, "error_rate": 0.001},
                {"id": "judgex-backend:8080", "avg_latency_ms": 3200.0, "error_rate": 0.185},
                {"id": "mysql-0:3306", "avg_latency_ms": 2800.0, "error_rate": 0.12},
                {"id": "redis:6379", "avg_latency_ms": 2.0, "error_rate": 0.0},
                {"id": "nsq:4150", "avg_latency_ms": 15.0, "error_rate": 0.01},
            ],
            "edges": [
                {"src": "nginx", "dst": "judgex-backend:8080", "avg_latency_ms": 5.0, "anomaly_score": 0.0},
                {"src": "judgex-backend:8080", "dst": "mysql-0:3306", "avg_latency_ms": 2800.0, "anomaly_score": 72.5},
                {"src": "judgex-backend:8080", "dst": "redis:6379", "avg_latency_ms": 2.0, "anomaly_score": 0.0},
            ],
        },
        ground_truth_root_cause="mysql-0:3306",
        expected_action="CONFIG_CHANGE",
        pattern="slow_query",
        expected_confidence_min=0.6,
        tags=["mysql", "connection-pool", "database"],
    ),
    BenchmarkScenario(
        name="mysql-slow-query-index-missing",
        description="Missing index on large table causes full table scan, high P99 latency",
        anomaly_event={
            "node_id": "backend:8080",
            "anomaly_score": 65.0,
            "avg_latency_ms": 4500.0,
            "call_count": 150,
            "suspect_chain": ["mysql-primary:3306", "backend:8080"],
            "timestamp_unix_nano": int(time.time() * 1e9),
        },
        topology={
            "nodes": [
                {"id": "gateway", "avg_latency_ms": 3.0, "error_rate": 0.0},
                {"id": "backend:8080", "avg_latency_ms": 4500.0, "error_rate": 0.05},
                {"id": "mysql-primary:3306", "avg_latency_ms": 4200.0, "error_rate": 0.03},
                {"id": "mysql-replica:3306", "avg_latency_ms": 50.0, "error_rate": 0.0},
            ],
            "edges": [
                {"src": "gateway", "dst": "backend:8080", "avg_latency_ms": 3.0, "anomaly_score": 0.0},
                {"src": "backend:8080", "dst": "mysql-primary:3306", "avg_latency_ms": 4200.0, "anomaly_score": 65.0},
                {"src": "backend:8080", "dst": "mysql-replica:3306", "avg_latency_ms": 50.0, "anomaly_score": 0.0},
            ],
        },
        ground_truth_root_cause="mysql-primary:3306",
        expected_action="CONFIG_CHANGE",
        pattern="slow_query",
        tags=["mysql", "index", "slow-query"],
    ),
    BenchmarkScenario(
        name="postgres-slow-query",
        description="PostgreSQL query planner chooses bad plan, rows estimated wrong",
        anomaly_event={
            "node_id": "user-service:8080",
            "anomaly_score": 58.0,
            "avg_latency_ms": 3800.0,
            "call_count": 200,
            "suspect_chain": ["postgres:5432", "user-service:8080"],
            "timestamp_unix_nano": int(time.time() * 1e9),
        },
        topology={
            "nodes": [
                {"id": "api-gateway", "avg_latency_ms": 2.0, "error_rate": 0.0},
                {"id": "user-service:8080", "avg_latency_ms": 3800.0, "error_rate": 0.08},
                {"id": "postgres:5432", "avg_latency_ms": 3500.0, "error_rate": 0.06},
                {"id": "redis:6379", "avg_latency_ms": 1.0, "error_rate": 0.0},
            ],
            "edges": [
                {"src": "api-gateway", "dst": "user-service:8080", "avg_latency_ms": 2.0, "anomaly_score": 0.0},
                {"src": "user-service:8080", "dst": "postgres:5432", "avg_latency_ms": 3500.0, "anomaly_score": 58.0},
                {"src": "user-service:8080", "dst": "redis:6379", "avg_latency_ms": 1.0, "anomaly_score": 0.0},
            ],
        },
        ground_truth_root_cause="postgres:5432",
        expected_action="CONFIG_CHANGE",
        pattern="slow_query",
        tags=["postgres", "database", "query-plan"],
    ),
    BenchmarkScenario(
        name="mongo-slow-aggregation",
        description="MongoDB aggregation pipeline without indexes, high CPU + latency",
        anomaly_event={
            "node_id": "analytics:8080",
            "anomaly_score": 70.0,
            "avg_latency_ms": 5500.0,
            "call_count": 80,
            "suspect_chain": ["mongo:27017", "analytics:8080"],
            "timestamp_unix_nano": int(time.time() * 1e9),
        },
        topology={
            "nodes": [
                {"id": "analytics:8080", "avg_latency_ms": 5500.0, "error_rate": 0.12},
                {"id": "mongo:27017", "avg_latency_ms": 5200.0, "error_rate": 0.10},
            ],
            "edges": [
                {"src": "analytics:8080", "dst": "mongo:27017", "avg_latency_ms": 5200.0, "anomaly_score": 70.0},
            ],
        },
        ground_truth_root_cause="mongo:27017",
        expected_action="CONFIG_CHANGE",
        pattern="slow_query",
        tags=["mongodb", "aggregation"],
    ),
    BenchmarkScenario(
        name="db-connection-leak",
        description="Application doesn't close DB connections, pool exhausted, gradual latency increase",
        anomaly_event={
            "node_id": "order-service:8080",
            "anomaly_score": 55.0,
            "avg_latency_ms": 2000.0,
            "call_count": 300,
            "suspect_chain": ["mysql:3306", "order-service:8080"],
            "timestamp_unix_nano": int(time.time() * 1e9),
        },
        topology={
            "nodes": [
                {"id": "order-service:8080", "avg_latency_ms": 2000.0, "error_rate": 0.07},
                {"id": "mysql:3306", "avg_latency_ms": 1800.0, "error_rate": 0.05},
            ],
            "edges": [
                {"src": "order-service:8080", "dst": "mysql:3306", "avg_latency_ms": 1800.0, "anomaly_score": 55.0},
            ],
        },
        ground_truth_root_cause="mysql:3306",
        expected_action="POD_RESTART",
        pattern="slow_query",
        expected_confidence_min=0.5,
        tags=["connection-leak", "mysql"],
    ),
    BenchmarkScenario(
        name="redis-slow-query",
        description="Redis has high latency due to large value operations (KEYS, SMEMBERS on huge sets)",
        anomaly_event={
            "node_id": "session-service:8080",
            "anomaly_score": 45.0,
            "avg_latency_ms": 1500.0,
            "call_count": 500,
            "suspect_chain": ["redis:6379", "session-service:8080"],
            "timestamp_unix_nano": int(time.time() * 1e9),
        },
        topology={
            "nodes": [
                {"id": "session-service:8080", "avg_latency_ms": 1500.0, "error_rate": 0.02},
                {"id": "redis:6379", "avg_latency_ms": 1400.0, "error_rate": 0.01},
            ],
            "edges": [
                {"src": "session-service:8080", "dst": "redis:6379", "avg_latency_ms": 1400.0, "anomaly_score": 45.0},
            ],
        },
        ground_truth_root_cause="redis:6379",
        expected_action="CONFIG_CHANGE",
        pattern="slow_query",
        tags=["redis", "slow-command"],
    ),

    # ── Pattern 2: Cache Avalanche / Miss Storm (5 scenarios) ──
    BenchmarkScenario(
        name="redis-cache-avalanche",
        description="Redis cache cluster down, all traffic hits DB, multiple services co-elevated",
        anomaly_event={
            "node_id": "payment-service:8080",
            "anomaly_score": 87.5,
            "avg_latency_ms": 2500.0,
            "call_count": 150,
            "suspect_chain": ["redis-cache:6379", "db-primary:5432", "payment-service:8080"],
            "timestamp_unix_nano": int(time.time() * 1e9),
        },
        topology={
            "nodes": [
                {"id": "payment-service:8080", "avg_latency_ms": 2500.0, "error_rate": 0.15},
                {"id": "order-service:8080", "avg_latency_ms": 2200.0, "error_rate": 0.12},
                {"id": "inventory:8080", "avg_latency_ms": 2100.0, "error_rate": 0.10},
                {"id": "redis-cache:6379", "avg_latency_ms": 5000.0, "error_rate": 0.95},
                {"id": "db-primary:5432", "avg_latency_ms": 2000.0, "error_rate": 0.08},
            ],
            "edges": [
                {"src": "payment-service:8080", "dst": "redis-cache:6379", "avg_latency_ms": 5000.0, "anomaly_score": 87.5},
                {"src": "payment-service:8080", "dst": "db-primary:5432", "avg_latency_ms": 2000.0, "anomaly_score": 40.0},
                {"src": "order-service:8080", "dst": "redis-cache:6379", "avg_latency_ms": 5000.0, "anomaly_score": 85.0},
                {"src": "inventory:8080", "dst": "redis-cache:6379", "avg_latency_ms": 5000.0, "anomaly_score": 82.0},
            ],
        },
        ground_truth_root_cause="redis-cache:6379",
        expected_action="SCALE_UP",
        pattern="cache_avalanche",
        expected_confidence_min=0.6,
        tags=["redis", "cache", "avalanche", "multi-service"],
    ),
    BenchmarkScenario(
        name="cache-ttl-misconfiguration",
        description="All cache keys TTL set to same time, mass expiration causes thundering herd",
        anomaly_event={
            "node_id": "feed-service:8080",
            "anomaly_score": 78.0,
            "avg_latency_ms": 3000.0,
            "call_count": 200,
            "suspect_chain": ["redis:6379", "db:5432", "feed-service:8080"],
            "timestamp_unix_nano": int(time.time() * 1e9),
        },
        topology={
            "nodes": [
                {"id": "feed-service:8080", "avg_latency_ms": 3000.0, "error_rate": 0.20},
                {"id": "recommend:8080", "avg_latency_ms": 2800.0, "error_rate": 0.18},
                {"id": "redis:6379", "avg_latency_ms": 100.0, "error_rate": 0.0},
                {"id": "db:5432", "avg_latency_ms": 2500.0, "error_rate": 0.15},
            ],
            "edges": [
                {"src": "feed-service:8080", "dst": "redis:6379", "avg_latency_ms": 100.0, "anomaly_score": 0.0},
                {"src": "feed-service:8080", "dst": "db:5432", "avg_latency_ms": 2500.0, "anomaly_score": 78.0},
                {"src": "recommend:8080", "dst": "redis:6379", "avg_latency_ms": 100.0, "anomaly_score": 0.0},
                {"src": "recommend:8080", "dst": "db:5432", "avg_latency_ms": 2500.0, "anomaly_score": 75.0},
            ],
        },
        ground_truth_root_cause="redis:6379",
        expected_action="CONFIG_CHANGE",
        pattern="cache_avalanche",
        tags=["cache", "ttl", "thundering-herd"],
    ),
    BenchmarkScenario(
        name="cdn-origin-cache-miss",
        description="CDN origin cache miss storm, all requests hit backend simultaneously",
        anomaly_event={
            "node_id": "static-server:8080",
            "anomaly_score": 90.0,
            "avg_latency_ms": 4000.0,
            "call_count": 1000,
            "suspect_chain": ["cdn-edge", "static-server:8080", "storage:9000"],
            "timestamp_unix_nano": int(time.time() * 1e9),
        },
        topology={
            "nodes": [
                {"id": "cdn-edge", "avg_latency_ms": 500.0, "error_rate": 0.0},
                {"id": "static-server:8080", "avg_latency_ms": 4000.0, "error_rate": 0.30},
                {"id": "storage:9000", "avg_latency_ms": 3500.0, "error_rate": 0.25},
            ],
            "edges": [
                {"src": "cdn-edge", "dst": "static-server:8080", "avg_latency_ms": 4000.0, "anomaly_score": 90.0},
                {"src": "static-server:8080", "dst": "storage:9000", "avg_latency_ms": 3500.0, "anomaly_score": 85.0},
            ],
        },
        ground_truth_root_cause="static-server:8080",
        expected_action="SCALE_UP",
        pattern="cache_avalanche",
        tags=["cdn", "cache-miss", "origin"],
    ),
    BenchmarkScenario(
        name="local-cache-poisoning",
        description="A bad deployment corrupted local cache, all nodes miss cache simultaneously",
        anomaly_event={
            "node_id": "web:8080",
            "anomaly_score": 82.0,
            "avg_latency_ms": 3500.0,
            "call_count": 400,
            "suspect_chain": ["web:8080", "api:8080"],
            "timestamp_unix_nano": int(time.time() * 1e9),
        },
        topology={
            "nodes": [
                {"id": "lb", "avg_latency_ms": 1.0, "error_rate": 0.0},
                {"id": "web:8080", "avg_latency_ms": 3500.0, "error_rate": 0.22},
                {"id": "web:8081", "avg_latency_ms": 3400.0, "error_rate": 0.20},
                {"id": "api:8080", "avg_latency_ms": 100.0, "error_rate": 0.0},
            ],
            "edges": [
                {"src": "lb", "dst": "web:8080", "avg_latency_ms": 3500.0, "anomaly_score": 82.0},
                {"src": "lb", "dst": "web:8081", "avg_latency_ms": 3400.0, "anomaly_score": 80.0},
                {"src": "web:8080", "dst": "api:8080", "avg_latency_ms": 100.0, "anomaly_score": 0.0},
            ],
        },
        ground_truth_root_cause="web:8080",
        expected_action="POD_RESTART",
        pattern="cache_avalanche",
        tags=["cache", "local-cache", "deployment"],
    ),
    BenchmarkScenario(
        name="memcached-outage",
        description="Memcached node went down, sessions all need to be re-established from DB",
        anomaly_event={
            "node_id": "auth-service:8080",
            "anomaly_score": 75.0,
            "avg_latency_ms": 2800.0,
            "call_count": 350,
            "suspect_chain": ["memcached:11211", "auth-service:8080", "user-db:5432"],
            "timestamp_unix_nano": int(time.time() * 1e9),
        },
        topology={
            "nodes": [
                {"id": "auth-service:8080", "avg_latency_ms": 2800.0, "error_rate": 0.18},
                {"id": "memcached:11211", "avg_latency_ms": 9999.0, "error_rate": 1.0},
                {"id": "user-db:5432", "avg_latency_ms": 500.0, "error_rate": 0.02},
            ],
            "edges": [
                {"src": "auth-service:8080", "dst": "memcached:11211", "avg_latency_ms": 9999.0, "anomaly_score": 75.0},
                {"src": "auth-service:8080", "dst": "user-db:5432", "avg_latency_ms": 500.0, "anomaly_score": 20.0},
            ],
        },
        ground_truth_root_cause="memcached:11211",
        expected_action="POD_RESTART",
        pattern="cache_avalanche",
        tags=["memcached", "cache", "session"],
    ),

    # ── Pattern 3: Network Congestion (5 scenarios) ──
    BenchmarkScenario(
        name="network-congestion-inter-az",
        description="Cross-AZ network congestion, all edges from one service show elevated latency",
        anomaly_event={
            "node_id": "svc-east:8080",
            "anomaly_score": 68.0,
            "avg_latency_ms": 800.0,
            "call_count": 500,
            "suspect_chain": ["svc-east:8080", "svc-west:8080"],
            "timestamp_unix_nano": int(time.time() * 1e9),
        },
        topology={
            "nodes": [
                {"id": "svc-east:8080", "avg_latency_ms": 800.0, "error_rate": 0.05},
                {"id": "svc-west:8080", "avg_latency_ms": 750.0, "error_rate": 0.04},
                {"id": "db-east:3306", "avg_latency_ms": 700.0, "error_rate": 0.03},
            ],
            "edges": [
                {"src": "svc-east:8080", "dst": "svc-west:8080", "avg_latency_ms": 750.0, "anomaly_score": 68.0},
                {"src": "svc-east:8080", "dst": "db-east:3306", "avg_latency_ms": 700.0, "anomaly_score": 65.0},
            ],
        },
        ground_truth_root_cause="svc-east:8080",
        expected_action="TC_DROP",
        pattern="network_congestion",
        tags=["network", "cross-az", "congestion"],
    ),
    BenchmarkScenario(
        name="traffic-surge-ddos",
        description="Sudden traffic surge from external, all incoming connections experience packet loss",
        anomaly_event={
            "node_id": "edge-proxy:443",
            "anomaly_score": 95.0,
            "avg_latency_ms": 5000.0,
            "call_count": 5000,
            "suspect_chain": ["edge-proxy:443", "app:8080"],
            "timestamp_unix_nano": int(time.time() * 1e9),
        },
        topology={
            "nodes": [
                {"id": "edge-proxy:443", "avg_latency_ms": 5000.0, "error_rate": 0.40},
                {"id": "app:8080", "avg_latency_ms": 300.0, "error_rate": 0.02},
                {"id": "db:3306", "avg_latency_ms": 10.0, "error_rate": 0.0},
            ],
            "edges": [
                {"src": "edge-proxy:443", "dst": "app:8080", "avg_latency_ms": 300.0, "anomaly_score": 50.0},
                {"src": "app:8080", "dst": "db:3306", "avg_latency_ms": 10.0, "anomaly_score": 0.0},
            ],
        },
        ground_truth_root_cause="edge-proxy:443",
        expected_action="TC_DROP",
        pattern="network_congestion",
        tags=["ddos", "traffic-surge", "edge"],
    ),
    BenchmarkScenario(
        name="dns-resolution-failure",
        description="DNS resolver slow, all external API calls timeout",
        anomaly_event={
            "node_id": "api-gateway:8080",
            "anomaly_score": 60.0,
            "avg_latency_ms": 6000.0,
            "call_count": 100,
            "suspect_chain": ["api-gateway:8080", "external-api"],
            "timestamp_unix_nano": int(time.time() * 1e9),
        },
        topology={
            "nodes": [
                {"id": "api-gateway:8080", "avg_latency_ms": 6000.0, "error_rate": 0.35},
                {"id": "dns-resolver:53", "avg_latency_ms": 5000.0, "error_rate": 0.50},
                {"id": "external-api", "avg_latency_ms": 200.0, "error_rate": 0.0},
            ],
            "edges": [
                {"src": "api-gateway:8080", "dst": "dns-resolver:53", "avg_latency_ms": 5000.0, "anomaly_score": 60.0},
                {"src": "api-gateway:8080", "dst": "external-api", "avg_latency_ms": 6000.0, "anomaly_score": 55.0},
            ],
        },
        ground_truth_root_cause="dns-resolver:53",
        expected_action="POD_RESTART",
        pattern="network_congestion",
        tags=["dns", "network", "timeout"],
    ),
    BenchmarkScenario(
        name="tcp-connection-leak",
        description="Application doesn't close TCP connections, FD exhaustion, new connections fail",
        anomaly_event={
            "node_id": "proxy:8080",
            "anomaly_score": 62.0,
            "avg_latency_ms": 900.0,
            "call_count": 200,
            "suspect_chain": ["proxy:8080", "backend:8080"],
            "timestamp_unix_nano": int(time.time() * 1e9),
        },
        topology={
            "nodes": [
                {"id": "proxy:8080", "avg_latency_ms": 900.0, "error_rate": 0.25},
                {"id": "backend:8080", "avg_latency_ms": 100.0, "error_rate": 0.0},
            ],
            "edges": [
                {"src": "proxy:8080", "dst": "backend:8080", "avg_latency_ms": 100.0, "anomaly_score": 0.0},
            ],
        },
        ground_truth_root_cause="proxy:8080",
        expected_action="POD_RESTART",
        pattern="network_congestion",
        tags=["tcp", "connection-leak", "fd"],
    ),
    BenchmarkScenario(
        name="load-balancer-misconfig",
        description="Load balancer health check misconfiguration, draining all traffic to one backend",
        anomaly_event={
            "node_id": "web-1:8080",
            "anomaly_score": 85.0,
            "avg_latency_ms": 4000.0,
            "call_count": 800,
            "suspect_chain": ["web-1:8080", "web-2:8080"],
            "timestamp_unix_nano": int(time.time() * 1e9),
        },
        topology={
            "nodes": [
                {"id": "lb", "avg_latency_ms": 2.0, "error_rate": 0.0},
                {"id": "web-1:8080", "avg_latency_ms": 4000.0, "error_rate": 0.30},
                {"id": "web-2:8080", "avg_latency_ms": 50.0, "error_rate": 0.0},
            ],
            "edges": [
                {"src": "lb", "dst": "web-1:8080", "avg_latency_ms": 4000.0, "anomaly_score": 85.0},
                {"src": "lb", "dst": "web-2:8080", "avg_latency_ms": 50.0, "anomaly_score": 0.0},
            ],
        },
        ground_truth_root_cause="lb",
        expected_action="CONFIG_CHANGE",
        pattern="network_congestion",
        tags=["load-balancer", "misconfiguration", "traffic"],
    ),

    # ── Pattern 4: Resource Exhaustion (7 scenarios) ──
    BenchmarkScenario(
        name="cpu-throttling",
        description="CPU throttling due to noisy neighbor, gradual latency ramp-up",
        anomaly_event={
            "node_id": "worker:8080",
            "anomaly_score": 55.0,
            "avg_latency_ms": 1800.0,
            "call_count": 400,
            "suspect_chain": ["worker:8080"],
            "timestamp_unix_nano": int(time.time() * 1e9),
        },
        topology={
            "nodes": [
                {"id": "queue", "avg_latency_ms": 5.0, "error_rate": 0.0},
                {"id": "worker:8080", "avg_latency_ms": 1800.0, "error_rate": 0.08},
            ],
            "edges": [
                {"src": "queue", "dst": "worker:8080", "avg_latency_ms": 1800.0, "anomaly_score": 55.0},
            ],
        },
        ground_truth_root_cause="worker:8080",
        expected_action="SCALE_UP",
        pattern="resource_exhaustion",
        tags=["cpu", "throttling", "resource"],
    ),
    BenchmarkScenario(
        name="memory-oom",
        description="Memory leak causes OOM kills, pod restart loop",
        anomaly_event={
            "node_id": "memory-hungry:8080",
            "anomaly_score": 80.0,
            "avg_latency_ms": 9999.0,
            "call_count": 50,
            "suspect_chain": ["memory-hungry:8080"],
            "timestamp_unix_nano": int(time.time() * 1e9),
        },
        topology={
            "nodes": [
                {"id": "memory-hungry:8080", "avg_latency_ms": 9999.0, "error_rate": 0.90},
            ],
            "edges": [],
        },
        ground_truth_root_cause="memory-hungry:8080",
        expected_action="POD_RESTART",
        pattern="resource_exhaustion",
        tags=["memory", "oom", "restart-loop"],
    ),
    BenchmarkScenario(
        name="disk-full",
        description="Disk full on logging partition, application can't write logs, hangs",
        anomaly_event={
            "node_id": "logger:8080",
            "anomaly_score": 70.0,
            "avg_latency_ms": 9999.0,
            "call_count": 10,
            "suspect_chain": ["logger:8080"],
            "timestamp_unix_nano": int(time.time() * 1e9),
        },
        topology={
            "nodes": [
                {"id": "logger:8080", "avg_latency_ms": 9999.0, "error_rate": 1.0},
            ],
            "edges": [],
        },
        ground_truth_root_cause="logger:8080",
        expected_action="POD_RESTART",
        pattern="resource_exhaustion",
        tags=["disk", "full", "storage"],
    ),
    BenchmarkScenario(
        name="connection-pool-exhaustion-app",
        description="Application HTTP connection pool exhausted, all outbound connections queue",
        anomaly_event={
            "node_id": "proxy:8080",
            "anomaly_score": 65.0,
            "avg_latency_ms": 3000.0,
            "call_count": 600,
            "suspect_chain": ["proxy:8080", "backend:8080"],
            "timestamp_unix_nano": int(time.time() * 1e9),
        },
        topology={
            "nodes": [
                {"id": "proxy:8080", "avg_latency_ms": 3000.0, "error_rate": 0.15},
                {"id": "backend:8080", "avg_latency_ms": 100.0, "error_rate": 0.0},
            ],
            "edges": [
                {"src": "proxy:8080", "dst": "backend:8080", "avg_latency_ms": 100.0, "anomaly_score": 0.0},
            ],
        },
        ground_truth_root_cause="proxy:8080",
        expected_action="SCALE_UP",
        pattern="resource_exhaustion",
        tags=["connection-pool", "http", "exhaustion"],
    ),
    BenchmarkScenario(
        name="goroutine-leak",
        description="Goroutine leak in Go service, thousands of goroutines stack up, GC pressure",
        anomaly_event={
            "node_id": "go-service:8080",
            "anomaly_score": 72.0,
            "avg_latency_ms": 2200.0,
            "call_count": 300,
            "suspect_chain": ["go-service:8080"],
            "timestamp_unix_nano": int(time.time() * 1e9),
        },
        topology={
            "nodes": [
                {"id": "go-service:8080", "avg_latency_ms": 2200.0, "error_rate": 0.10},
            ],
            "edges": [],
        },
        ground_truth_root_cause="go-service:8080",
        expected_action="POD_RESTART",
        pattern="resource_exhaustion",
        tags=["goroutine", "leak", "go", "gc"],
    ),
    BenchmarkScenario(
        name="file-descriptor-exhaustion",
        description="Too many open files, can't accept new connections",
        anomaly_event={
            "node_id": "server:8080",
            "anomaly_score": 78.0,
            "avg_latency_ms": 9999.0,
            "call_count": 5,
            "suspect_chain": ["server:8080"],
            "timestamp_unix_nano": int(time.time() * 1e9),
        },
        topology={
            "nodes": [
                {"id": "server:8080", "avg_latency_ms": 9999.0, "error_rate": 0.95},
            ],
            "edges": [],
        },
        ground_truth_root_cause="server:8080",
        expected_action="POD_RESTART",
        pattern="resource_exhaustion",
        tags=["file-descriptor", "fd", "ulimit"],
    ),
    BenchmarkScenario(
        name="thread-pool-exhaustion",
        description="Thread pool exhausted in Java service, task queue grows unbounded",
        anomaly_event={
            "node_id": "java-service:8080",
            "anomaly_score": 68.0,
            "avg_latency_ms": 4500.0,
            "call_count": 250,
            "suspect_chain": ["java-service:8080"],
            "timestamp_unix_nano": int(time.time() * 1e9),
        },
        topology={
            "nodes": [
                {"id": "java-service:8080", "avg_latency_ms": 4500.0, "error_rate": 0.12},
            ],
            "edges": [],
        },
        ground_truth_root_cause="java-service:8080",
        expected_action="SCALE_UP",
        pattern="resource_exhaustion",
        tags=["thread-pool", "java", "exhaustion"],
    ),

    # ── Pattern 5: Hot Spot / Inefficient Algorithm (5 scenarios) ──
    BenchmarkScenario(
        name="hot-spot-shard",
        description="Database hot shard: one shard gets 90% of traffic, others idle",
        anomaly_event={
            "node_id": "db-shard-3:3306",
            "anomaly_score": 90.0,
            "avg_latency_ms": 5000.0,
            "call_count": 900,
            "suspect_chain": ["db-shard-3:3306"],
            "timestamp_unix_nano": int(time.time() * 1e9),
        },
        topology={
            "nodes": [
                {"id": "db-shard-1:3306", "avg_latency_ms": 10.0, "error_rate": 0.0},
                {"id": "db-shard-2:3306", "avg_latency_ms": 15.0, "error_rate": 0.0},
                {"id": "db-shard-3:3306", "avg_latency_ms": 5000.0, "error_rate": 0.35},
                {"id": "db-shard-4:3306", "avg_latency_ms": 12.0, "error_rate": 0.0},
            ],
            "edges": [
                {"src": "app:8080", "dst": "db-shard-3:3306", "avg_latency_ms": 5000.0, "anomaly_score": 90.0},
                {"src": "app:8080", "dst": "db-shard-1:3306", "avg_latency_ms": 10.0, "anomaly_score": 0.0},
            ],
        },
        ground_truth_root_cause="db-shard-3:3306",
        expected_action="CONFIG_CHANGE",
        pattern="hot_spot",
        tags=["database", "shard", "hot-spot"],
    ),
    BenchmarkScenario(
        name="inefficient-n-plus-one",
        description="N+1 query pattern in ORM, exponential latency growth with data size",
        anomaly_event={
            "node_id": "catalog:8080",
            "anomaly_score": 60.0,
            "avg_latency_ms": 3500.0,
            "call_count": 100,
            "suspect_chain": ["catalog:8080", "mysql:3306"],
            "timestamp_unix_nano": int(time.time() * 1e9),
        },
        topology={
            "nodes": [
                {"id": "catalog:8080", "avg_latency_ms": 3500.0, "error_rate": 0.05},
                {"id": "mysql:3306", "avg_latency_ms": 100.0, "error_rate": 0.0},
            ],
            "edges": [
                {"src": "catalog:8080", "dst": "mysql:3306", "avg_latency_ms": 100.0, "anomaly_score": 0.0},
            ],
        },
        ground_truth_root_cause="catalog:8080",
        expected_action="IMAGE_ROLLBACK",
        pattern="hot_spot",
        tags=["n-plus-1", "orm", "inefficient"],
    ),
    BenchmarkScenario(
        name="bad-deployment-regression",
        description="New deployment includes a regression, CPU-intensive code path on every request",
        anomaly_event={
            "node_id": "search:8080",
            "anomaly_score": 75.0,
            "avg_latency_ms": 2800.0,
            "call_count": 300,
            "suspect_chain": ["search:8080"],
            "timestamp_unix_nano": int(time.time() * 1e9),
        },
        topology={
            "nodes": [
                {"id": "search:8080", "avg_latency_ms": 2800.0, "error_rate": 0.08},
                {"id": "index:9200", "avg_latency_ms": 50.0, "error_rate": 0.0},
            ],
            "edges": [
                {"src": "search:8080", "dst": "index:9200", "avg_latency_ms": 50.0, "anomaly_score": 0.0},
            ],
        },
        ground_truth_root_cause="search:8080",
        expected_action="IMAGE_ROLLBACK",
        pattern="hot_spot",
        tags=["deployment", "regression", "rollback"],
    ),
    BenchmarkScenario(
        name="rate-limiter-too-aggressive",
        description="Rate limiter misconfigured, throttling legitimate traffic",
        anomaly_event={
            "node_id": "api:8080",
            "anomaly_score": 50.0,
            "avg_latency_ms": 100.0,
            "call_count": 50,
            "suspect_chain": ["api:8080"],
            "timestamp_unix_nano": int(time.time() * 1e9),
        },
        topology={
            "nodes": [
                {"id": "api:8080", "avg_latency_ms": 100.0, "error_rate": 0.45},
            ],
            "edges": [],
        },
        ground_truth_root_cause="api:8080",
        expected_action="CONFIG_CHANGE",
        pattern="hot_spot",
        tags=["rate-limiter", "misconfiguration", "throttle"],
    ),
    BenchmarkScenario(
        name="feature-flag-bad-path",
        description="New feature flag enabled a slow code path, P95 isolated spike on single service",
        anomaly_event={
            "node_id": "recommend:8080",
            "anomaly_score": 55.0,
            "avg_latency_ms": 2000.0,
            "call_count": 200,
            "suspect_chain": ["recommend:8080"],
            "timestamp_unix_nano": int(time.time() * 1e9),
        },
        topology={
            "nodes": [
                {"id": "recommend:8080", "avg_latency_ms": 2000.0, "error_rate": 0.03},
            ],
            "edges": [],
        },
        ground_truth_root_cause="recommend:8080",
        expected_action="CONFIG_CHANGE",
        pattern="hot_spot",
        tags=["feature-flag", "regression", "config"],
    ),

    # ── Edge cases (2 scenarios) ──
    BenchmarkScenario(
        name="no-anomaly-false-positive",
        description="Normal traffic spike during flash sale, no actual fault",
        anomaly_event={
            "node_id": "checkout:8080",
            "anomaly_score": 30.0,
            "avg_latency_ms": 800.0,
            "call_count": 2000,
            "suspect_chain": ["checkout:8080", "inventory:8080"],
            "timestamp_unix_nano": int(time.time() * 1e9),
        },
        topology={
            "nodes": [
                {"id": "checkout:8080", "avg_latency_ms": 800.0, "error_rate": 0.01},
                {"id": "inventory:8080", "avg_latency_ms": 100.0, "error_rate": 0.0},
            ],
            "edges": [
                {"src": "checkout:8080", "dst": "inventory:8080", "avg_latency_ms": 100.0, "anomaly_score": 0.0},
            ],
        },
        ground_truth_root_cause="",
        expected_action="",
        pattern="hot_spot",
        tags=["false-positive", "traffic-surge", "normal"],
    ),
    BenchmarkScenario(
        name="multi-fault-simultaneous",
        description="Two independent faults: Redis cache down AND MySQL slow query simultaneously",
        anomaly_event={
            "node_id": "composite:8080",
            "anomaly_score": 92.0,
            "avg_latency_ms": 6000.0,
            "call_count": 400,
            "suspect_chain": ["redis:6379", "mysql:3306", "composite:8080"],
            "timestamp_unix_nano": int(time.time() * 1e9),
        },
        topology={
            "nodes": [
                {"id": "composite:8080", "avg_latency_ms": 6000.0, "error_rate": 0.40},
                {"id": "redis:6379", "avg_latency_ms": 9999.0, "error_rate": 0.90},
                {"id": "mysql:3306", "avg_latency_ms": 5000.0, "error_rate": 0.30},
            ],
            "edges": [
                {"src": "composite:8080", "dst": "redis:6379", "avg_latency_ms": 9999.0, "anomaly_score": 92.0},
                {"src": "composite:8080", "dst": "mysql:3306", "avg_latency_ms": 5000.0, "anomaly_score": 70.0},
            ],
        },
        ground_truth_root_cause="redis:6379",  # More severe fault wins
        expected_action="SCALE_UP",
        pattern="cache_avalanche",
        tags=["multi-fault", "composite", "edge-case"],
    ),
]


def get_scenario(name: str) -> BenchmarkScenario:
    """Get a scenario by name."""
    for s in SCENARIOS:
        if s.name == name:
            return s
    raise KeyError(f"Scenario '{name}' not found")


def get_scenarios_by_pattern(pattern: str) -> List[BenchmarkScenario]:
    """Get all scenarios matching a pattern."""
    return [s for s in SCENARIOS if s.pattern == pattern]


def get_scenarios_by_tag(tag: str) -> List[BenchmarkScenario]:
    """Get all scenarios with a specific tag."""
    return [s for s in SCENARIOS if tag in s.tags]
