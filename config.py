import os
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent
INSTANCE_DIR = BASE_DIR / "instance"


class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "change-me-for-production")
    SQLALCHEMY_DATABASE_URI = os.getenv(
        "DATABASE_URL",
        f"sqlite:///{(INSTANCE_DIR / 'traffic_analyzer.db').as_posix()}",
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    HOST = os.getenv("HOST", "127.0.0.1")
    PORT = int(os.getenv("PORT", "5000"))
    DEBUG = os.getenv("FLASK_DEBUG", "0") == "1"

    SNAPSHOT_INTERVAL_SECONDS = int(os.getenv("SNAPSHOT_INTERVAL_SECONDS", "5"))
    TIME_SERIES_POINTS = int(os.getenv("TIME_SERIES_POINTS", "30"))
    DEFAULT_PACKET_PAGE_SIZE = int(os.getenv("DEFAULT_PACKET_PAGE_SIZE", "25"))
    DEMO_PACKET_INTERVAL_SECONDS = float(
        os.getenv("DEMO_PACKET_INTERVAL_SECONDS", "0.55")
    )

    DEFAULT_THRESHOLDS = {
        "PORT_SCAN_PORT_THRESHOLD": 10,
        "HIGH_PACKET_RATE_THRESHOLD": 35,
        "DNS_REPEAT_THRESHOLD": 8,
        "ICMP_BURST_THRESHOLD": 10,
        "TRAFFIC_BURST_BYTES_THRESHOLD": 12000,
        "SYN_SCAN_THRESHOLD": 12,
        "PROTOCOL_SPIKE_THRESHOLD": 18,
        "WINDOW_SECONDS": 10,
    }
