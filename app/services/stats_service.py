import threading
import time
from collections import Counter, deque
from datetime import datetime

from .. import db
from ..models import AlertLog, TrafficSnapshot


class StatsService:
    def __init__(self, app, socketio):
        self.app = app
        self.socketio = socketio
        self.lock = threading.Lock()
        self.snapshot_interval = app.config["SNAPSHOT_INTERVAL_SECONDS"]
        self.max_points = app.config["TIME_SERIES_POINTS"]
        self.reset_state(load_alerts=True)

    def reset_state(self, load_alerts=False):
        with self.lock:
            self.total_packets = 0
            self.total_bytes = 0
            self.protocol_counter = Counter()
            self.src_counter = Counter()
            self.dst_counter = Counter()
            self.talker_counter = Counter()
            self.packet_buckets = deque(maxlen=self.max_points)
            self.active_alerts = 0
            self.last_snapshot_at = time.time()
            self.last_capture_state = {
                "status": "stopped",
                "mode": "idle",
                "interface": "",
            }

        if load_alerts:
            with self.app.app_context():
                active = AlertLog.query.filter_by(status="New").count()
            with self.lock:
                self.active_alerts = active

    def process_packet(self, packet, capture_state=None, emit=True):
        now = packet.get("timestamp") or datetime.utcnow()
        length = int(packet.get("length") or 0)
        protocol = packet.get("protocol") or "Unknown"
        src_ip = packet.get("src_ip") or "Unknown"
        dst_ip = packet.get("dst_ip") or "Unknown"
        talker = f"{src_ip} -> {dst_ip}"

        with self.lock:
            if capture_state:
                self.last_capture_state = dict(capture_state)
            self.total_packets += 1
            self.total_bytes += length
            self.protocol_counter[protocol] += 1
            self.src_counter[src_ip] += 1
            self.dst_counter[dst_ip] += 1
            self.talker_counter[talker] += length
            self._update_buckets(now, length)
            snapshot_needed = time.time() - self.last_snapshot_at >= self.snapshot_interval
            if snapshot_needed:
                self.last_snapshot_at = time.time()
            overview = self._build_overview_locked(capture_state)
            snapshot = self._build_snapshot_locked() if snapshot_needed else None

        if snapshot:
            self._persist_snapshot(snapshot)
        if emit:
            self.socketio.emit("stats_update", overview)
        return overview

    def register_alert(self):
        with self.lock:
            self.active_alerts += 1

    def mark_alert_reviewed(self):
        with self.lock:
            self.active_alerts = max(0, self.active_alerts - 1)

    def get_overview(self, capture_state=None):
        with self.lock:
            if capture_state:
                self.last_capture_state = dict(capture_state)
            return self._build_overview_locked(capture_state)

    def set_capture_state(self, capture_state):
        with self.lock:
            self.last_capture_state = dict(capture_state)

    def get_protocol_distribution(self):
        with self.lock:
            return [
                {"label": label, "value": value}
                for label, value in self.protocol_counter.most_common()
            ]

    def get_timeseries(self):
        with self.lock:
            labels = [bucket["label"] for bucket in self.packet_buckets]
            packets = [bucket["packets"] for bucket in self.packet_buckets]
            bandwidth = [bucket["bandwidth_bps"] for bucket in self.packet_buckets]
            return {"labels": labels, "packets": packets, "bandwidth": bandwidth}

    def get_top_talkers(self, limit=5):
        with self.lock:
            talkers = [
                {"label": label, "value": value}
                for label, value in self.talker_counter.most_common(limit)
            ]
            sources = [
                {"label": label, "value": value}
                for label, value in self.src_counter.most_common(limit)
            ]
            destinations = [
                {"label": label, "value": value}
                for label, value in self.dst_counter.most_common(limit)
            ]
        return {
            "talkers": talkers,
            "sources": sources,
            "destinations": destinations,
        }

    def _build_overview_locked(self, capture_state=None):
        capture_state = capture_state or self.last_capture_state
        dominant_protocol = (
            self.protocol_counter.most_common(1)[0][0] if self.protocol_counter else "N/A"
        )
        current_bandwidth = (
            self.packet_buckets[-1]["bandwidth_bps"] if self.packet_buckets else 0
        )
        latest_label = self.packet_buckets[-1]["label"] if self.packet_buckets else "-"

        payload = {
            "total_packets": self.total_packets,
            "total_bytes": self.total_bytes,
            "active_alerts": self.active_alerts,
            "current_bandwidth_bps": current_bandwidth,
            "dominant_protocol": dominant_protocol,
            "last_bucket_label": latest_label,
            "packet_trend": {
                "labels": [bucket["label"] for bucket in self.packet_buckets],
                "values": [bucket["packets"] for bucket in self.packet_buckets],
            },
            "bandwidth_trend": {
                "labels": [bucket["label"] for bucket in self.packet_buckets],
                "values": [bucket["bandwidth_bps"] for bucket in self.packet_buckets],
            },
            "protocol_distribution": [
                {"label": label, "value": value}
                for label, value in self.protocol_counter.most_common()
            ],
            "top_talkers": [
                {"label": label, "value": value}
                for label, value in self.talker_counter.most_common(5)
            ],
        }
        if capture_state:
            payload.update(
                {
                    "capture_status": capture_state.get("status", "stopped"),
                    "selected_interface": capture_state.get("interface") or "Not selected",
                    "capture_mode": capture_state.get("mode") or "idle",
                }
            )
        return payload

    def _build_snapshot_locked(self):
        dominant_protocol = (
            self.protocol_counter.most_common(1)[0][0] if self.protocol_counter else "N/A"
        )
        bandwidth = self.packet_buckets[-1]["bandwidth_bps"] if self.packet_buckets else 0
        return {
            "timestamp": datetime.utcnow(),
            "total_packets": self.total_packets,
            "total_bytes": self.total_bytes,
            "bandwidth_bps": bandwidth,
            "dominant_protocol": dominant_protocol,
            "active_alerts": self.active_alerts,
        }

    def _persist_snapshot(self, snapshot):
        with self.app.app_context():
            record = TrafficSnapshot(**snapshot)
            db.session.add(record)
            db.session.commit()

    def _update_buckets(self, now, length):
        label = now.strftime("%H:%M:%S")
        if not self.packet_buckets or self.packet_buckets[-1]["label"] != label:
            self.packet_buckets.append(
                {
                    "label": label,
                    "packets": 0,
                    "bytes": 0,
                    "bandwidth_bps": 0,
                }
            )
        bucket = self.packet_buckets[-1]
        bucket["packets"] += 1
        bucket["bytes"] += length
        bucket["bandwidth_bps"] = bucket["bytes"] * 8
