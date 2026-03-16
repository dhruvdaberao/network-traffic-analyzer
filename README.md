# Intelligent Network Traffic Analyzer

Intelligent Network Traffic Analyzer is a resume-grade academic project that captures or simulates network traffic, parses packet metadata, detects suspicious behavior with rule-based logic, stores summaries in SQLite, and streams live analytics to a professional dashboard.

## Elevator Pitch

This project demonstrates how a systems engineer can build an end-to-end monitoring workflow: packet ingestion, protocol-aware parsing, short-window anomaly detection, persistence, live dashboard updates, and export/report support in a clean Flask application.

## Features

- Live capture mode with interface selection using Scapy
- Automatic demo mode fallback when live sniffing is unavailable
- Real-time packet parsing for TCP, UDP, ICMP, DNS, HTTP, HTTPS/TLS, ARP, and other traffic
- Rule-based suspicious traffic detection for port scans, SYN-heavy activity, DNS repetition, traffic bursts, ICMP bursts, protocol spikes, and high packet rate
- SQLite persistence for packet summaries, alerts, and traffic snapshots
- Real-time dashboard updates with Flask-SocketIO
- Packet search/filtering and alert review workflow
- CSV export for packet logs and alert logs
- Clean, dark, enterprise-style UI for demos and interviews

## Tech Stack

- Backend: Python 3.11+, Flask, Flask-SocketIO, SQLAlchemy, Scapy, SQLite
- Frontend: HTML, CSS, Vanilla JavaScript, Chart.js, Socket.IO client
- Utilities: psutil, threading, Python logging

## Folder Structure

```text
intelligent-network-traffic-analyzer/
├── app.py
├── config.py
├── requirements.txt
├── README.md
├── .env.example
├── instance/
├── sample_data/
├── app/
│   ├── __init__.py
│   ├── models.py
│   ├── routes.py
│   ├── socket_events.py
│   ├── services/
│   │   ├── __init__.py
│   │   ├── capture_service.py
│   │   ├── packet_parser.py
│   │   ├── detection_engine.py
│   │   ├── stats_service.py
│   │   ├── export_service.py
│   │   └── demo_traffic_generator.py
│   ├── static/
│   │   ├── css/style.css
│   │   └── js/dashboard.js
│   └── templates/
│       ├── base.html
│       ├── index.html
│       ├── live.html
│       ├── alerts.html
│       ├── packets.html
│       └── settings.html
```

## Setup Instructions

### 1. Create and activate a virtual environment

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

Edit `.env` if needed. The app runs with sensible defaults even without it.

### 4. Start the application

```powershell
python app.py
```

Open [http://127.0.0.1:5000](http://127.0.0.1:5000).

## Running Demo Mode

Demo mode is the safest way to present the project in interviews or on systems without packet capture privileges.

1. Start the Flask app.
2. Open the **Settings** page.
3. Click **Start Demo Mode**.
4. Observe realistic browsing, DNS, HTTPS bursts, ICMP activity, port scan patterns, and repeated DNS behavior in the dashboard.

## Running Live Capture Mode

1. Install Npcap on Windows with WinPcap compatibility enabled.
2. Run PowerShell or Command Prompt as Administrator when needed.
3. Start the Flask app.
4. Go to **Settings**.
5. Select a network interface.
6. Click **Start Live Capture**.

If live capture fails, the backend automatically falls back to demo mode so the dashboard remains usable.

## Detection Logic

The detection engine maintains short rolling windows in memory and generates alerts when thresholds are crossed:

- Port Scan: same source probing many destination ports on the same host
- High Packet Rate: one source emitting too many packets in the active window
- Repeated DNS Requests: repeated queries for the same domain
- ICMP Burst: repeated ICMP packets from the same source
- Traffic Burst: aggregate bytes exceeding the current window threshold
- Protocol Spike: sudden increase in one protocol volume
- Suspicious SYN Pattern: repeated SYN-only attempts to multiple targets

Thresholds are editable from the **Settings** page and persisted in the SQLite database.

## Architecture Overview

1. `capture_service.py` starts either a Scapy sniffer or the demo traffic generator.
2. `packet_parser.py` converts packets into a defensive, normalized metadata dictionary.
3. `capture_service.py` writes packet summaries to SQLite.
4. `stats_service.py` maintains running counters and traffic time buckets.
5. `detection_engine.py` evaluates each packet against rule windows and stores alerts.
6. Flask APIs and Socket.IO push data to the dashboard in real time.

## Database Design

Core tables:

- `PacketLog`: normalized packet metadata and summary text
- `AlertLog`: suspicious activity alerts with severity, threshold, and review status
- `TrafficSnapshot`: periodic overview snapshots for historical summaries
- `AppSetting`: persisted capture and threshold settings

## Screenshots

Add screenshots here before submitting the project:

- `docs/screenshots/overview.png`
- `docs/screenshots/live-feed.png`
- `docs/screenshots/alerts.png`
- `docs/screenshots/settings.png`

## How This Project Demonstrates Systems Engineering Skills

- Understands packet-level networking concepts and protocol classification
- Handles privilege-sensitive operations with graceful fallback design
- Uses defensive parsing and avoids raw payload storage for safer monitoring
- Builds a full observability loop: ingest, parse, detect, persist, stream, export
- Separates concerns into capture, parsing, statistics, detection, and presentation services
- Produces a demo-friendly system that can be explained clearly in an interview

## Limitations

- HTTP inspection is lightweight and only parses simple request metadata when readable payloads exist
- HTTPS/TLS is inferred by port instead of deep TLS parsing
- Live packet capture quality depends on OS permissions, installed drivers, and chosen interface
- The detection engine is intentionally rule-based and not ML-driven
- Chart.js and Socket.IO client libraries are loaded from CDNs in the browser

## Future Improvements

- Add authenticated user roles and audit actions
- Store historical dashboard aggregates for long-running trend analysis
- Add PCAP replay support and offline upload analysis
- Add richer DNS/HTTP parsing and TLS fingerprinting
- Implement alert suppression, grouping, and severity tuning policies
- Add PDF summary report generation

## Troubleshooting

- Live capture shows no interfaces:
  Install Npcap and restart the terminal.
- Live capture fails on Windows:
  Run the terminal as Administrator and verify Npcap is installed correctly.
- Dashboard opens but charts do not render:
  Check browser internet access because Chart.js and Socket.IO client are loaded via CDN.
- Packets do not appear:
  Start demo mode first to verify the application pipeline works end to end.

## Security and Safety Note

This is an educational traffic monitoring project only. It performs detection and visualization only. It does not include offensive tooling, payload execution, credential interception, MITM logic, or exploit capabilities.

## Resume-Ready Project Description

Built an intelligent network traffic analyzer using Flask, Scapy, SQLite, and Socket.IO to capture or simulate packets in real time, classify protocols, detect suspicious patterns such as port scans and DNS abuse, persist analytics, and present live observability data in a professional dashboard.
