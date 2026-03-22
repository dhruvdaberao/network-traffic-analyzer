# Intelligent Network Traffic Analyzer

A Flask + Socket.IO network monitoring dashboard that can either capture live packets from a local interface or run a built-in demo traffic generator. The app parses packets, stores summaries in SQLite, computes traffic statistics, raises rule-based alerts, and streams updates to a responsive dashboard.

## Key Features

- Live packet capture with interface selection and start-up validation
- Demo mode that exercises the same analytics pipeline without packet-sniffing requirements
- Real-time dashboard updates over Socket.IO
- Protocol-aware parsing for TCP, UDP, ICMP, ARP, DNS, HTTP, and HTTPS/TLS inference
- Rule-based detection for port scans, DNS repetition, ICMP bursts, SYN-heavy behavior, and traffic spikes
- Searchable packet history, alert review workflow, and CSV export
- Mobile-friendly dashboard layout for overview, live traffic, alerts, packets, and settings

## Tech Stack

- **Backend:** Python, Flask, Flask-SocketIO, SQLAlchemy, SQLite, Scapy, psutil
- **Frontend:** HTML, CSS, vanilla JavaScript, Chart.js, Socket.IO client
- **Runtime model:** threaded packet capture/demo generation with real-time event emission

## Architecture Summary

1. `capture_service.py` starts live capture or demo generation.
2. `packet_parser.py` normalizes packet metadata.
3. `models.py` persists packets, alerts, snapshots, and app settings.
4. `stats_service.py` updates overview metrics and historical buckets.
5. `detection_engine.py` evaluates packets against short-window detection rules.
6. `routes.py` exposes page routes, JSON APIs, and export endpoints.
7. `dashboard.js` hydrates the UI from APIs and Socket.IO events.

## Folder Structure

```text
.
├── app.py
├── config.py
├── README.md
├── REPORT.md
├── app/
│   ├── __init__.py
│   ├── models.py
│   ├── routes.py
│   ├── socket_events.py
│   ├── services/
│   │   ├── capture_service.py
│   │   ├── demo_traffic_generator.py
│   │   ├── detection_engine.py
│   │   ├── export_service.py
│   │   ├── packet_parser.py
│   │   └── stats_service.py
│   ├── static/
│   │   ├── css/style.css
│   │   └── js/dashboard.js
│   └── templates/
│       ├── alerts.html
│       ├── base.html
│       ├── index.html
│       ├── live.html
│       ├── packets.html
│       └── settings.html
└── instance/
    └── traffic_analyzer.db
```

## Setup and Run

### 1. Create and activate a virtual environment

```bash
python -m venv .venv
source .venv/bin/activate  # Linux / macOS
# or .venv\Scripts\activate on Windows
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

### 3. Start the application

```bash
python app.py
```

Open `http://127.0.0.1:5000`.

## Demo Mode vs Live Capture

### Demo mode

Use demo mode when you want a reliable walkthrough of the full analytics pipeline.

- No packet-capture permissions required
- Safe for hosted deployments, cloud demos, and portfolio screenshots
- Exercises parsing, stats, detection, storage, charts, and exports

### Live capture

Use live capture when running locally on a machine that can sniff traffic.

Typical requirements:

- A usable local network interface
- Sufficient privileges to sniff packets
- Scapy installed correctly
- **Windows:** Npcap or compatible capture support

The app now validates live-capture readiness and returns explicit failure reasons instead of silently masking errors.

## Limitations

- Hosted deployments generally cannot inspect the traffic on your personal device
- HTTPS/TLS payloads are not decrypted; protocol classification is inferred from metadata and ports
- SQLite and in-memory windows are appropriate for demos and moderate local sessions, not large-scale production traffic ingestion
- Detection is rule-based and explainable by design, not ML-based

## Usage Summary

- **Overview:** session metrics, charts, recent packets, recent alerts
- **Live Traffic:** scrolling packet feed and session snapshot
- **Alerts:** severity-tagged detections with review workflow and CSV export
- **Packets:** searchable, filterable packet log with pagination and CSV export
- **Settings:** capture controls, readiness messaging, threshold tuning, and data reset

## Additional Technical Detail

For a deeper system walkthrough, troubleshooting notes, module-by-module explanation, and design rationale, see [`REPORT.md`](REPORT.md).
