# REPORT.md — Intelligent Network Traffic Analyzer

## System Overview

The Intelligent Network Traffic Analyzer is a Flask-based monitoring application that supports two ingestion paths:

1. **Live capture** through Scapy on a selected local interface.
2. **Demo capture** through a deterministic traffic generator that simulates normal and suspicious traffic patterns.

Both modes feed the same downstream pipeline: packet normalization, persistence, statistics aggregation, detection, Socket.IO emission, and frontend rendering.

## End-to-End Workflow

1. The user starts capture from the Settings page.
2. `CaptureService` validates the runtime, interface selection, and dependency readiness.
3. Incoming packets are normalized by `packet_parser.py`.
4. Packet metadata is stored in `PacketLog`.
5. `StatsService` updates totals, bandwidth buckets, protocol counters, and snapshot state.
6. `DetectionEngine` evaluates the packet against short sliding-window rules.
7. Alerts are stored in `AlertLog` and emitted through Socket.IO.
8. The frontend updates overview cards, charts, packet tables, and the live feed.

## Module-by-Module Explanation

### `app.py`
Launches the Socket.IO-enabled Flask application.

### `config.py`
Provides environment-driven configuration including host, port, demo timing, snapshot timing, and default detection thresholds.

### `app/__init__.py`
Creates the Flask app, configures logging, initializes SQLAlchemy and Socket.IO, registers services, creates tables, and optionally auto-starts demo mode in hosted mode.

### `app/models.py`
Defines:

- `PacketLog`
- `AlertLog`
- `TrafficSnapshot`
- `AppSetting`

### `app/routes.py`
Exposes page routes, JSON APIs, capture controls, threshold updates, clear-data operations, and CSV exports.

### `app/socket_events.py`
Pushes initial capture status and overview data to newly connected clients.

### `app/services/capture_service.py`
Responsibilities:

- interface enumeration
- live-capture validation
- hosted/container readiness messaging
- demo-mode startup
- live-capture lifecycle management
- packet pipeline entry point
- capture-status emission

### `app/services/packet_parser.py`
Normalizes either Scapy packets or demo dictionaries into a consistent schema containing timestamp, flow metadata, protocol classification, direction, and summary text.

### `app/services/stats_service.py`
Maintains in-memory counters and rolling buckets for:

- total packets
- total bytes
- active alerts
- protocol distribution
- top talkers
- bandwidth trend
- periodic snapshot persistence

### `app/services/detection_engine.py`
Maintains sliding windows using `deque` and emits alerts with cooldowns to avoid repeated spam.

### `app/services/export_service.py`
Exports alerts and packets as CSV attachments.

### `app/services/demo_traffic_generator.py`
Creates repeatable demo scenarios including:

- web browsing
- DNS lookups
- HTTPS traffic
- file-download bursts
- ICMP sequences
- SYN/port-scan behavior
- repeated DNS patterns

## Detection Rules in Detail

### Port Scan
Tracks distinct destination ports from one source to one destination inside the active window.

### High Packet Rate
Flags unusually high packet counts per source within the configured window.

### Repeated DNS Requests
Flags repeated identical DNS queries from the same source.

### ICMP Burst
Flags repeated ICMP packets from the same source.

### Traffic Burst
Flags aggregate byte spikes across all traffic.

### Protocol Spike
Flags sudden bursts of a given protocol type.

### Suspicious SYN Pattern
Tracks SYN-only behavior across distinct targets to surface scan-like traffic.

## Database Schema Notes

### `PacketLog`
Stores normalized packet summaries and search/filter metadata.

### `AlertLog`
Stores detection outputs, severity, threshold context, and review status.

### `TrafficSnapshot`
Stores periodic analytics snapshots for historical summaries.

### `AppSetting`
Stores lightweight persisted configuration such as selected capture mode, interface, and thresholds.

## API Summary

### Page Routes

- `/`
- `/live`
- `/alerts`
- `/packets`
- `/settings`

### JSON APIs

- `GET /api/overview`
- `GET /api/traffic/protocol-distribution`
- `GET /api/traffic/bandwidth`
- `GET /api/traffic/top-talkers`
- `GET /api/packets`
- `GET /api/alerts`
- `POST /api/alerts/<id>/review`
- `POST /api/capture/start`
- `POST /api/capture/demo-start`
- `POST /api/capture/stop`
- `GET /api/interfaces`
- `GET /api/settings/current`
- `POST /api/settings/thresholds`
- `POST /api/settings/clear-data`
- `GET /api/export/alerts`
- `GET /api/export/packets`

### Socket Events

- `capture_status`
- `stats_update`
- `live_packet`
- `alert_update`

## Live Capture Design Notes

The most important hardening change is that live-capture startup now performs explicit validation and returns structured error responses. Previously, the service frequently hid failures by falling back to demo mode and returning success, which made the app appear unreliable and hard to debug.

The current design checks:

- hosted mode
- Scapy availability
- Windows capture readiness
- presence of a usable interface
- whether the selected interface actually exists
- startup exceptions such as permission or interface failures

## Windows / Npcap / Permissions Notes

On Windows, live capture usually requires:

- Npcap installed
- occasionally WinPcap compatibility mode
- a supported network adapter
- enough privilege to sniff packets

If those prerequisites are missing, the app now surfaces a direct status message instead of implying that live capture should work the same way it does in demo mode.

## Practical Limitations

- Cloud-hosted deployments generally cannot capture traffic from the viewer's machine
- Containerized environments may expose interfaces that are not meaningful for an end-user demo
- Encrypted HTTPS payloads are not decrypted
- SQLite and in-memory counters are best suited for demos, development, and smaller local runs

## Design Choices

- **Explainable rules over opaque ML:** easier to demo and defend
- **SQLite for simplicity:** easy local setup, predictable persistence
- **Socket.IO for reactivity:** keeps dashboard latency low without polling-heavy pages
- **Demo mode parity:** allows consistent walkthroughs in restricted environments

## Troubleshooting Guide

### Live capture says hosted environment
Run locally or disable hosted mode in environments where raw sniffing is allowed.

### Live capture says Scapy unavailable
Install Scapy and verify platform packet-capture support.

### Live capture says Npcap required
Install Npcap on Windows and retry.

### Live capture says no usable interface
Verify that the host exposes active interfaces and that the selected name matches a real adapter.

### Live capture says insufficient permissions
Retry with elevated privileges or grant packet-capture permissions.

### Demo mode works but live mode does not
That usually indicates an environment or privilege issue rather than a downstream parsing or dashboard problem.

## Future Enhancements

- PCAP import and replay workflow
- Retention policies for old packets and snapshots
- richer alert grouping and suppression controls
- authentication and multi-user roles
- background job queue for high-volume analysis
- optional historical dashboards across sessions

## Interview Preparation Notes

This project is easy to explain around a few themes:

- dual-mode ingestion for reliable demos and realistic local capture
- normalization of heterogeneous packet inputs into one analytics pipeline
- short-window rule detection with explainable tradeoffs
- operational honesty about hosted-environment limitations
- responsive frontend design for a technical dashboard product
