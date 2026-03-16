# Intelligent Network Traffic Analyzer

Intelligent Network Traffic Analyzer is a placement-ready full-stack systems project that captures or simulates network traffic, parses packet metadata in real time, detects suspicious patterns using rule-based logic, stores summaries in SQLite, and presents live analytics on a professional dashboard.

This project is designed to be understandable, demo-friendly, and realistic for systems engineering interviews. It supports both real packet capture and a built-in demo mode, so the full workflow can be demonstrated even when Windows permissions, drivers, or packet sniffing dependencies are unavailable.

## Project Overview

The system continuously ingests packets from either:

- a live network interface using Scapy
- or a demo traffic generator that simulates realistic browsing, DNS lookups, HTTPS traffic, traffic bursts, ICMP activity, and suspicious behavior

Each packet is normalized into a consistent metadata structure, stored in SQLite, processed by a statistics engine, checked against suspicious traffic detection rules, and streamed to the frontend through Socket.IO for real-time UI updates.

The result is a compact network monitoring platform that demonstrates:

- packet inspection and protocol awareness
- backend service design
- database modeling
- rule-based detection logic
- live dashboard engineering
- Windows-friendly operational thinking

## Key Features

- Real-time packet capture from a selected interface
- Demo mode for interviews, presentations, and restricted environments
- Defensive packet parsing with graceful handling of incomplete or malformed packets
- Protocol identification for:
  - TCP
  - UDP
  - ICMP
  - DNS
  - HTTP
  - HTTPS/TLS inference
  - ARP
  - Other / Unknown
- Packet metadata extraction including timestamp, IPs, ports, length, TCP flags, DNS query, HTTP host/method, direction, and summary
- Live overview dashboard with metrics, charts, recent packets, and recent alerts
- Rule-based suspicious traffic detection
- Alert persistence with severity and review status
- Searchable packet table
- CSV export for alerts and packet logs
- Configurable thresholds for detection logic

## Tech Stack

### Backend

- Python 3.11+
- Flask
- Flask-SocketIO
- SQLAlchemy
- SQLite
- Scapy
- psutil
- Python logging
- threading

### Frontend

- HTML5
- CSS3
- Vanilla JavaScript
- Chart.js
- Socket.IO client

## Architecture

The application is intentionally modular and follows a service-oriented structure that is still easy to explain in an interview.

### Flow

1. `capture_service.py` starts either live capture or demo traffic generation.
2. `packet_parser.py` converts each packet into a normalized metadata dictionary.
3. The normalized packet is persisted in `PacketLog`.
4. `stats_service.py` updates session-level counters, protocol distribution, bandwidth, and top talkers.
5. `detection_engine.py` checks the packet against short-window suspicious traffic rules.
6. Alerts are stored in `AlertLog` and emitted live through Socket.IO.
7. The frontend consumes APIs for initial page data and Socket.IO for live updates.

### Core Services

- `capture_service.py`
  Handles live capture startup, demo mode fallback, background threading, and packet pipeline entry.

- `packet_parser.py`
  Performs protocol classification and safe metadata extraction.

- `stats_service.py`
  Maintains in-memory traffic metrics and periodic snapshot persistence.

- `detection_engine.py`
  Implements short-window suspicious traffic detection using deques and counters.

- `export_service.py`
  Exports alerts and packets as CSV downloads.

## Folder Structure

```text
intelligent-network-traffic-analyzer/
├── app.py
├── config.py
├── requirements.txt
├── README.md
├── .env.example
├── instance/
│   └── traffic_analyzer.db
├── sample_data/
│   └── README.md
└── app/
    ├── __init__.py
    ├── models.py
    ├── routes.py
    ├── socket_events.py
    ├── services/
    │   ├── __init__.py
    │   ├── capture_service.py
    │   ├── packet_parser.py
    │   ├── detection_engine.py
    │   ├── stats_service.py
    │   ├── export_service.py
    │   └── demo_traffic_generator.py
    ├── static/
    │   ├── css/
    │   │   └── style.css
    │   └── js/
    │       └── dashboard.js
    └── templates/
        ├── base.html
        ├── index.html
        ├── live.html
        ├── alerts.html
        ├── packets.html
        └── settings.html
```

## Database Schema

### PacketLog

Stores packet summaries and normalized metadata:

- timestamp
- src_ip
- dst_ip
- src_port
- dst_port
- protocol
- length
- tcp_flags
- dns_query
- http_host
- http_method
- direction
- summary

### AlertLog

Stores suspicious traffic alerts:

- timestamp
- src_ip
- dst_ip
- alert_type
- severity
- reason
- metric_value
- threshold_value
- status

### TrafficSnapshot

Stores periodic session snapshots:

- timestamp
- total_packets
- total_bytes
- bandwidth_bps
- dominant_protocol
- active_alerts

### AppSetting

Stores lightweight persisted settings such as:

- capture mode
- selected interface
- detection thresholds

## Setup Instructions

### 1. Create a virtual environment

Windows PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

### 2. Install dependencies

```powershell
pip install -r requirements.txt
```

### 3. Configure environment variables

```powershell
Copy-Item .env.example .env
```

The application also works with defaults if `.env` is not present, but using `.env` is cleaner for local development.

### 4. Run the application

```powershell
python app.py
```

Open:

- [http://127.0.0.1:5000](http://127.0.0.1:5000)

## Demo Mode

Demo mode is the safest and most reliable way to present this project during placements or interviews.

### Why demo mode matters

- It does not require packet capture permissions.
- It does not require Npcap or a supported sniffing setup.
- It exercises the exact same parsing, stats, alerting, storage, and dashboard pipeline as live mode.
- It generates realistic events that make the dashboard visibly useful in a short demo.

### Demo traffic includes

- Normal HTTP browsing
- DNS lookups
- HTTPS/TLS traffic
- Download burst traffic
- ICMP sequence traffic
- Port-scan-like SYN probing
- Repeated DNS request behavior

### How to use demo mode

1. Start the app.
2. Open the `Settings` page.
3. Click `Start Demo Mode`.
4. Watch the overview metrics, live feed, alerts, and packet table update automatically.

## Windows Live-Capture Notes

This project is designed to run on Windows, but live capture depends on system privileges and packet capture support.

### Requirements for live capture on Windows

- Install Npcap
- Prefer enabling WinPcap compatibility during installation
- Run the terminal as Administrator if required by your system configuration
- Use a valid network interface shown on the Settings page

### Important Windows behavior

- If Scapy is installed but packet capture still fails, the app catches the error and falls back to demo mode.
- If Scapy is missing, the app still runs and demo mode remains fully usable.
- SQLite path handling uses a local `instance` directory and works cleanly on Windows.
- Background capture is handled using Python threads to keep the Flask UI responsive.

### Recommended Windows demo workflow

For interviews, start in demo mode first to prove the system end to end. Then optionally show live mode and explain the privilege and driver requirements clearly.

## Suspicious Traffic Detection Rules

The detection engine is intentionally rule-based so the logic is explainable in an interview.

### Implemented rules

- Port Scan
  Detects one source hitting many destination ports on the same destination within a short window.

- High Packet Rate
  Detects unusually high packet volume from a single source IP.

- Repeated DNS Requests
  Detects repeated queries for the same domain from the same source.

- ICMP Burst
  Detects repeated ICMP packets that may indicate flood-like behavior.

- Traffic Burst
  Detects abnormal aggregate traffic volume in a short time window.

- Protocol Spike
  Detects sudden concentration of one protocol type in the active window.

- Suspicious SYN Pattern
  Detects repeated SYN-only traffic to many targets, useful for scan-like behavior.

### Detection approach

- Uses short in-memory rolling windows with `deque`
- Stores alerts in SQLite
- Emits alerts live to the dashboard
- Supports threshold tuning from the Settings page

This keeps the project practical and defensible without introducing unnecessary complexity.

## Dashboard Pages

### Overview

- Total packets
- Total bytes
- Active alerts
- Current bandwidth
- Selected interface
- Capture status
- Packets-over-time chart
- Bandwidth chart
- Protocol distribution chart
- Top talkers chart
- Recent packets
- Recent alerts

### Live Traffic

- Scrolling live packet summaries
- Protocol filtering
- Pause/resume feed
- Session metrics

### Alerts

- Alert table
- Severity badges
- Source and destination context
- Review workflow
- CSV export

### Packets

- Searchable packet table
- Filters by protocol, source IP, destination IP, and text
- Pagination
- CSV export

### Settings

- Start live capture
- Start demo mode
- Stop capture
- Select interface
- Adjust detection thresholds
- Clear stored data

## API Endpoints

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

- `live_packet`
- `stats_update`
- `alert_update`
- `capture_status`

## Stability and Practical Design Choices

- No raw payload storage beyond lightweight HTTP/DNS metadata
- Defensive parsing to avoid crashes on malformed packets
- Demo mode uses the same downstream pipeline as live mode
- Detection logic is explainable and configurable
- Persistent storage is local and simple through SQLite
- UI remains responsive through background capture threads

## Limitations

- HTTP parsing is lightweight and only extracts simple readable request metadata
- HTTPS/TLS is inferred by well-known ports rather than decrypted deep inspection
- Long-running capture sessions are not optimized for high-volume production use
- The detection engine is rule-based, not machine-learning-based
- Live capture quality depends on OS permissions, drivers, and interface availability

## Future Enhancements

- PCAP file import and replay mode
- Historical trend analytics across sessions
- PDF report generation
- Alert grouping and suppression logic
- Better TLS fingerprinting and richer protocol parsing
- Authentication and multi-user dashboards
- Optional PostgreSQL support for larger datasets

## Interview Explanation

This project is strong for systems and full-stack interviews because it demonstrates both infrastructure awareness and application engineering:

- understanding of packet capture constraints on Windows
- practical protocol parsing
- real-time event-driven backend updates
- database-backed monitoring workflows
- anomaly detection using rolling windows
- professional dashboard presentation
- safe fallback behavior when dependencies or privileges are missing

## Resume-Ready Project Description

Use this directly or adapt it:

**Intelligent Network Traffic Analyzer**  
Built a real-time network traffic analyzer using Python, Flask, Scapy, SQLite, and Socket.IO to capture or simulate packets, classify protocols, compute live traffic analytics, detect suspicious behaviors such as port scans and repeated DNS activity, persist alerts and packet summaries, and present results in a professional dashboard with demo-mode fallback for Windows environments with restricted packet capture permissions.

## Short Resume Version

Built a Flask- and Scapy-based network traffic analyzer with real-time packet parsing, suspicious traffic detection, SQLite persistence, live dashboard updates, and Windows-friendly demo-mode fallback.

## Security and Ethics Note

This project is intended for educational monitoring and analysis only. It focuses on detection, observability, and safe visualization. It does not include offensive tooling, exploitation, credential interception, malware behavior, or packet payload abuse.
