import json
import logging
import time
from collections import defaultdict, deque

from .. import db
from ..models import AlertLog, AppSetting


class DetectionEngine:
    def __init__(self, app, socketio, stats_service):
        self.app = app
        self.socketio = socketio
        self.stats_service = stats_service
        self.logger = logging.getLogger(__name__)
        self.thresholds = dict(app.config["DEFAULT_THRESHOLDS"])
        self.alert_cooldowns = {}
        self.port_scan_window = defaultdict(deque)
        self.packet_rate_window = defaultdict(deque)
        self.dns_window = defaultdict(deque)
        self.icmp_window = defaultdict(deque)
        self.syn_window = defaultdict(deque)
        self.traffic_burst_window = deque()
        self.protocol_window = defaultdict(deque)
        self._load_saved_thresholds()

    def get_thresholds(self):
        return dict(self.thresholds)

    def update_thresholds(self, values):
        for key in self.thresholds:
            if key in values:
                try:
                    self.thresholds[key] = int(values[key])
                except (TypeError, ValueError):
                    continue
        with self.app.app_context():
            AppSetting.set_value("detection_thresholds", json.dumps(self.thresholds))
        return {
            "success": True,
            "message": "Detection thresholds updated.",
            "thresholds": self.get_thresholds(),
        }

    def reset_state(self):
        self.port_scan_window.clear()
        self.packet_rate_window.clear()
        self.dns_window.clear()
        self.icmp_window.clear()
        self.syn_window.clear()
        self.traffic_burst_window.clear()
        self.protocol_window.clear()
        self.alert_cooldowns.clear()

    def process_packet(self, packet):
        now = time.time()
        src = packet.get("src_ip") or "unknown"
        dst = packet.get("dst_ip") or "unknown"
        protocol = packet.get("protocol") or "Unknown"
        window_seconds = self.thresholds["WINDOW_SECONDS"]

        self._append_and_trim(self.packet_rate_window[src], now, window_seconds)
        self._append_and_trim(self.protocol_window[protocol], now, window_seconds)
        self._append_and_trim(
            self.traffic_burst_window, (now, packet.get("length", 0)), window_seconds
        )

        if packet.get("dst_port") is not None:
            self._append_and_trim(
                self.port_scan_window[(src, dst)],
                (now, packet["dst_port"]),
                window_seconds,
            )

        if protocol == "DNS" and packet.get("dns_query"):
            self._append_and_trim(
                self.dns_window[(src, packet["dns_query"])], now, window_seconds
            )

        if protocol == "ICMP":
            self._append_and_trim(self.icmp_window[src], now, window_seconds)

        if protocol in {"TCP", "HTTP", "HTTPS/TLS"} and packet.get("tcp_flags"):
            flags = packet["tcp_flags"]
            if "S" in flags and "A" not in flags:
                self._append_and_trim(
                    self.syn_window[src],
                    (now, dst, packet.get("dst_port")),
                    window_seconds,
                )

        self._check_port_scan(src, dst)
        self._check_high_packet_rate(src)
        self._check_dns_repeat(src, packet.get("dns_query"))
        self._check_icmp_burst(src)
        self._check_traffic_burst()
        self._check_protocol_spike(protocol)
        self._check_syn_attempts(src)

    def _check_port_scan(self, src, dst):
        threshold = self.thresholds["PORT_SCAN_PORT_THRESHOLD"]
        distinct_ports = {port for _, port in self.port_scan_window.get((src, dst), [])}
        if len(distinct_ports) >= threshold:
            self._emit_alert(
                alert_key=("port_scan", src, dst),
                src_ip=src,
                dst_ip=dst,
                alert_type="Port Scan",
                severity="High",
                reason=(
                    f"Observed {len(distinct_ports)} destination ports probed by {src} "
                    f"against {dst} within {self.thresholds['WINDOW_SECONDS']} seconds."
                ),
                metric_value=float(len(distinct_ports)),
                threshold_value=float(threshold),
            )

    def _check_high_packet_rate(self, src):
        threshold = self.thresholds["HIGH_PACKET_RATE_THRESHOLD"]
        count = len(self.packet_rate_window.get(src, []))
        if count >= threshold:
            severity = "Critical" if count >= threshold * 1.5 else "High"
            self._emit_alert(
                alert_key=("high_packet_rate", src),
                src_ip=src,
                dst_ip=None,
                alert_type="High Packet Rate",
                severity=severity,
                reason=(
                    f"Source {src} generated {count} packets in the last "
                    f"{self.thresholds['WINDOW_SECONDS']} seconds."
                ),
                metric_value=float(count),
                threshold_value=float(threshold),
            )

    def _check_dns_repeat(self, src, query):
        if not query:
            return
        threshold = self.thresholds["DNS_REPEAT_THRESHOLD"]
        count = len(self.dns_window.get((src, query), []))
        if count >= threshold:
            self._emit_alert(
                alert_key=("dns_repeat", src, query),
                src_ip=src,
                dst_ip=None,
                alert_type="Repeated DNS Requests",
                severity="Medium",
                reason=(
                    f"Source {src} repeated DNS query '{query}' {count} times "
                    f"in {self.thresholds['WINDOW_SECONDS']} seconds."
                ),
                metric_value=float(count),
                threshold_value=float(threshold),
            )

    def _check_icmp_burst(self, src):
        threshold = self.thresholds["ICMP_BURST_THRESHOLD"]
        count = len(self.icmp_window.get(src, []))
        if count >= threshold:
            self._emit_alert(
                alert_key=("icmp_burst", src),
                src_ip=src,
                dst_ip=None,
                alert_type="ICMP Burst",
                severity="High",
                reason=(
                    f"Detected {count} ICMP packets from {src} inside the active analysis window."
                ),
                metric_value=float(count),
                threshold_value=float(threshold),
            )

    def _check_traffic_burst(self):
        threshold = self.thresholds["TRAFFIC_BURST_BYTES_THRESHOLD"]
        total_bytes = sum(length for _, length in self.traffic_burst_window)
        if total_bytes >= threshold:
            self._emit_alert(
                alert_key=("traffic_burst", "global"),
                src_ip=None,
                dst_ip=None,
                alert_type="Traffic Burst",
                severity="Critical" if total_bytes >= threshold * 1.5 else "High",
                reason=(
                    f"Aggregate observed traffic reached {total_bytes} bytes within "
                    f"{self.thresholds['WINDOW_SECONDS']} seconds."
                ),
                metric_value=float(total_bytes),
                threshold_value=float(threshold),
            )

    def _check_protocol_spike(self, protocol):
        threshold = self.thresholds["PROTOCOL_SPIKE_THRESHOLD"]
        count = len(self.protocol_window.get(protocol, []))
        if count >= threshold:
            severity = "Medium" if count < threshold * 1.5 else "High"
            self._emit_alert(
                alert_key=("protocol_spike", protocol),
                src_ip=None,
                dst_ip=None,
                alert_type="Protocol Spike",
                severity=severity,
                reason=(
                    f"Protocol {protocol} appeared {count} times in the last "
                    f"{self.thresholds['WINDOW_SECONDS']} seconds."
                ),
                metric_value=float(count),
                threshold_value=float(threshold),
            )

    def _check_syn_attempts(self, src):
        threshold = self.thresholds["SYN_SCAN_THRESHOLD"]
        count = len(self.syn_window.get(src, []))
        if count >= threshold:
            distinct_targets = {(dst, port) for _, dst, port in self.syn_window.get(src, [])}
            self._emit_alert(
                alert_key=("syn_attempts", src),
                src_ip=src,
                dst_ip=None,
                alert_type="Suspicious SYN Pattern",
                severity="High",
                reason=(
                    f"Source {src} sent {count} SYN-only attempts to "
                    f"{len(distinct_targets)} distinct socket targets."
                ),
                metric_value=float(count),
                threshold_value=float(threshold),
            )

    def _emit_alert(
        self,
        alert_key,
        src_ip,
        dst_ip,
        alert_type,
        severity,
        reason,
        metric_value,
        threshold_value,
    ):
        now = time.time()
        if now - self.alert_cooldowns.get(tuple(alert_key), 0) < self.thresholds["WINDOW_SECONDS"]:
            return

        self.alert_cooldowns[tuple(alert_key)] = now
        with self.app.app_context():
            alert = AlertLog(
                src_ip=src_ip,
                dst_ip=dst_ip,
                alert_type=alert_type,
                severity=severity,
                reason=reason,
                metric_value=metric_value,
                threshold_value=threshold_value,
            )
            db.session.add(alert)
            db.session.commit()
            payload = alert.to_dict()

        self.stats_service.register_alert()
        self.socketio.emit("alert_update", payload)
        self.socketio.emit("stats_update", self.stats_service.get_overview())
        self.logger.warning("Alert generated: %s", reason)

    def _append_and_trim(self, window, value, window_seconds):
        window.append(value)
        now = time.time()
        while window:
            first = window[0]
            first_time = first[0] if isinstance(first, tuple) else first
            if now - first_time <= window_seconds:
                break
            window.popleft()

    def _load_saved_thresholds(self):
        with self.app.app_context():
            payload = AppSetting.get_value("detection_thresholds")
        if not payload:
            return
        try:
            loaded = json.loads(payload)
        except json.JSONDecodeError:
            self.logger.warning("Saved detection thresholds were invalid JSON.")
            return

        for key in self.thresholds:
            if key in loaded:
                try:
                    self.thresholds[key] = int(loaded[key])
                except (TypeError, ValueError):
                    continue
