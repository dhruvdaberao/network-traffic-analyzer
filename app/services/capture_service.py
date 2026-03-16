import logging
import threading
from datetime import datetime
from socket import AF_INET

import psutil

from .. import db
from ..models import AppSetting, PacketLog
from .demo_traffic_generator import DemoTrafficGenerator
from .packet_parser import parse_packet

try:
    from scapy.all import AsyncSniffer, get_if_list
except Exception:  # pragma: no cover
    AsyncSniffer = None
    get_if_list = None


class CaptureService:
    def __init__(self, app, socketio, stats_service, detection_engine):
        self.app = app
        self.socketio = socketio
        self.stats_service = stats_service
        self.detection_engine = detection_engine
        self.logger = logging.getLogger(__name__)
        self.lock = threading.Lock()
        self.stop_event = threading.Event()
        self.sniffer = None
        self.demo_thread = None
        self.status = "stopped"
        self.mode = "idle"
        self.interface = None
        self.message = "Capture idle."
        self.last_error = ""
        self.local_ips = self._collect_local_ips()
        with self.app.app_context():
            self.mode = AppSetting.get_value("capture_mode", "idle")
            self.interface = AppSetting.get_value("capture_interface", "")

    def get_status(self):
        with self.lock:
            return {
                "status": self.status,
                "mode": self.mode,
                "interface": self.interface,
                "message": self.message,
                "error": self.last_error,
            }

    def get_interfaces(self):
        psutil_addrs = psutil.net_if_addrs()
        names = set(psutil_addrs.keys())
        if get_if_list:
            try:
                names.update(get_if_list())
            except Exception:
                self.logger.exception("Failed to list Scapy interfaces.")

        items = []
        for name in sorted(names):
            ipv4 = [
                addr.address
                for addr in psutil_addrs.get(name, [])
                if getattr(addr, "family", None) == AF_INET
            ]
            items.append({"name": name, "ipv4": ipv4})
        return items

    def start_live(self, interface_name=None):
        with self.lock:
            self._stop_locked(emit=False)
            self.mode = "live"
            self.interface = interface_name or self.interface
            self.status = "starting"
            self.message = "Starting live capture."
            self.last_error = ""

        self._emit_status()

        if not AsyncSniffer:
            return self.start_demo(
                "Scapy live sniffing is unavailable. Demo mode started automatically."
            )

        if not self.interface:
            interfaces = self.get_interfaces()
            if interfaces:
                self.interface = interfaces[0]["name"]

        try:
            self.local_ips = self._collect_local_ips(self.interface)
            self.sniffer = AsyncSniffer(
                iface=self.interface,
                prn=self._handle_live_packet,
                store=False,
            )
            self.sniffer.start()
            with self.lock:
                self.status = "running"
                self.message = "Live capture running."
            self._persist_capture_settings()
            self._emit_status()
            return {
                "success": True,
                "mode": "live",
                "message": "Live capture started.",
                "status": self.get_status(),
            }
        except Exception as exc:
            self.logger.exception("Failed to start live capture.")
            return self.start_demo(
                f"Live capture unavailable ({exc}). Demo mode started automatically."
            )

    def start_demo(self, message=None):
        with self.lock:
            self._stop_locked(emit=False)
            self.stop_event = threading.Event()
            self.mode = "demo"
            self.interface = "Demo Traffic Generator"
            self.status = "running"
            self.message = message or "Demo traffic generator running."
            self.last_error = ""

        generator = DemoTrafficGenerator(
            callback=self._handle_demo_packet,
            stop_event=self.stop_event,
            interval_seconds=self.app.config["DEMO_PACKET_INTERVAL_SECONDS"],
        )
        self.demo_thread = threading.Thread(target=generator.run, daemon=True)
        self.demo_thread.start()
        self._persist_capture_settings()
        self._emit_status()
        return {
            "success": True,
            "mode": "demo",
            "message": self.message,
            "status": self.get_status(),
        }

    def stop_capture(self):
        with self.lock:
            self._stop_locked(emit=False)
        self._emit_status()
        return {
            "success": True,
            "message": "Capture stopped.",
            "status": self.get_status(),
        }

    def _stop_locked(self, emit=False):
        self.stop_event.set()
        if self.sniffer:
            try:
                self.sniffer.stop()
            except Exception:
                self.logger.exception("Stopping sniffer failed.")
            finally:
                self.sniffer = None
        self.demo_thread = None
        self.status = "stopped"
        self.message = "Capture stopped."
        self.last_error = ""
        if emit:
            self._emit_status()

    def _handle_live_packet(self, packet):
        self._process_packet(packet)

    def _handle_demo_packet(self, packet):
        self._process_packet(packet)

    def _process_packet(self, packet):
        try:
            parsed = parse_packet(packet, local_ips=self.local_ips)
            with self.app.app_context():
                packet_log = PacketLog(
                    timestamp=parsed["timestamp"],
                    src_ip=parsed.get("src_ip"),
                    dst_ip=parsed.get("dst_ip"),
                    src_port=parsed.get("src_port"),
                    dst_port=parsed.get("dst_port"),
                    protocol=parsed.get("protocol"),
                    length=parsed.get("length"),
                    tcp_flags=parsed.get("tcp_flags"),
                    dns_query=parsed.get("dns_query"),
                    http_host=parsed.get("http_host"),
                    http_method=parsed.get("http_method"),
                    direction=parsed.get("direction"),
                    summary=parsed.get("summary") or "Packet captured",
                )
                db.session.add(packet_log)
                db.session.commit()
                parsed["id"] = packet_log.id
                parsed["timestamp"] = packet_log.timestamp.isoformat()

            stats_payload = self.stats_service.process_packet(
                {**parsed, "timestamp": _timestamp_from_iso(parsed["timestamp"])},
                capture_state=self.get_status(),
                emit=False,
            )
            self.detection_engine.process_packet(parsed)
            self.socketio.emit("live_packet", parsed)
            self.socketio.emit("stats_update", stats_payload)
        except Exception:
            self.logger.exception("Packet processing failed.")

    def _emit_status(self):
        status = self.get_status()
        self.stats_service.set_capture_state(status)
        self.socketio.emit("capture_status", status)

    def _persist_capture_settings(self):
        with self.app.app_context():
            AppSetting.set_value("capture_mode", self.mode)
            AppSetting.set_value("capture_interface", self.interface or "")

    def _collect_local_ips(self, preferred_interface=None):
        local_ips = set()
        for name, addresses in psutil.net_if_addrs().items():
            if preferred_interface and name != preferred_interface:
                continue
            for address in addresses:
                if getattr(address, "family", None) == AF_INET:
                    local_ips.add(address.address)
        return local_ips


def _timestamp_from_iso(value):
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return datetime.utcnow()
