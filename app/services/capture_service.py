import logging
import os
import platform
import threading
from datetime import datetime
from socket import AF_INET

import psutil

from .. import db
from ..models import AppSetting, PacketLog
from .demo_traffic_generator import DemoTrafficGenerator
from .packet_parser import parse_packet

try:
    from scapy.all import AsyncSniffer, conf, get_if_list
except Exception:  # pragma: no cover
    AsyncSniffer = None
    conf = None
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
        self.last_failure_code = ""
        self.environment = self.inspect_environment()
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
                "failure_code": self.last_failure_code,
                "environment": self.environment,
            }

    def inspect_environment(self):
        system = platform.system().lower()
        hosted_mode = bool(self.app.config.get("HOSTED_MODE"))
        running_in_container = os.path.exists("/.dockerenv") or os.getenv("K_SERVICE") is not None
        scapy_available = AsyncSniffer is not None
        windows_npcap_ready = True
        warnings = []

        if system == "windows":
            windows_npcap_ready = self._detect_windows_pcap_support()
            if not windows_npcap_ready:
                warnings.append("Npcap or WinPcap-compatible capture support was not detected.")

        if hosted_mode:
            warnings.append("Hosted mode is enabled, so live capture is intentionally disabled.")
        elif running_in_container:
            warnings.append(
                "Containerized or hosted environments often cannot access a meaningful local network interface for packet sniffing."
            )

        if not scapy_available:
            warnings.append("Scapy live sniffing dependencies are unavailable.")

        return {
            "platform": platform.system(),
            "hosted_mode": hosted_mode,
            "running_in_container": running_in_container,
            "scapy_available": scapy_available,
            "windows_npcap_ready": windows_npcap_ready,
            "can_attempt_live_capture": scapy_available and not hosted_mode,
            "warnings": warnings,
        }

    def get_interfaces(self):
        psutil_addrs = psutil.net_if_addrs()
        stats = psutil.net_if_stats()
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
            iface_stats = stats.get(name)
            is_up = bool(iface_stats.isup) if iface_stats else False
            speed = getattr(iface_stats, "speed", 0) if iface_stats else 0
            usable = is_up or bool(ipv4)
            items.append(
                {
                    "name": name,
                    "ipv4": ipv4,
                    "is_up": is_up,
                    "speed_mbps": speed,
                    "usable": usable,
                }
            )
        return items

    def start_live(self, interface_name=None):
        self.environment = self.inspect_environment()
        requested_interface = (interface_name or self.interface or "").strip()
        self.logger.info("Live capture requested. interface=%s environment=%s", requested_interface or "<auto>", self.environment)

        with self.lock:
            demo_thread = self._stop_locked(emit=False)
            self.mode = "live"
            self.interface = requested_interface
            self.status = "starting"
            self.message = "Validating live capture requirements."
            self.last_error = ""
            self.last_failure_code = ""

        self._join_demo_thread(demo_thread)
        self._emit_status()

        diagnostics = self._validate_live_start(requested_interface)
        if not diagnostics["ok"]:
            return self._live_failure_response(
                diagnostics["code"],
                diagnostics["message"],
                selected_interface=diagnostics.get("interface") or requested_interface,
            )

        selected_interface = diagnostics["interface"]
        try:
            self.local_ips = self._collect_local_ips(selected_interface)
            self.sniffer = AsyncSniffer(
                iface=selected_interface,
                prn=self._handle_live_packet,
                store=False,
            )
            self.sniffer.start()
            with self.lock:
                self.interface = selected_interface
                self.status = "running"
                self.message = f"Live capture running on {selected_interface}."
                self.last_error = ""
                self.last_failure_code = ""
            self._persist_capture_settings()
            self._emit_status()
            self.logger.info("Live capture started successfully on %s", selected_interface)
            return {
                "success": True,
                "mode": "live",
                "message": f"Live capture started successfully on {selected_interface}.",
                "status": self.get_status(),
            }
        except PermissionError as exc:
            self.logger.exception("Insufficient permissions to start live capture.")
            return self._live_failure_response(
                "insufficient_permissions",
                f"Capture failed due to insufficient permissions: {exc}",
                selected_interface=selected_interface,
            )
        except Exception as exc:
            self.logger.exception("Failed to start live capture.")
            return self._live_failure_response(
                self._classify_start_exception(exc),
                f"Live capture failed to start on {selected_interface}: {exc}",
                selected_interface=selected_interface,
            )

    def start_demo(self, message=None):
        with self.lock:
            demo_thread = self._stop_locked(emit=False)
            self.stop_event = threading.Event()
            self.mode = "demo"
            self.interface = "Demo Traffic Generator"
            self.status = "running"
            self.message = message or "Demo mode active — analytics pipeline is fully exercised."
            self.last_error = ""
            self.last_failure_code = ""
            self.local_ips = {"192.168.1.23"}

        self._join_demo_thread(demo_thread)
        generator = DemoTrafficGenerator(
            callback=self._handle_demo_packet,
            stop_event=self.stop_event,
            interval_seconds=self.app.config["DEMO_PACKET_INTERVAL_SECONDS"],
        )
        self.demo_thread = threading.Thread(target=generator.run, daemon=True)
        self.demo_thread.start()
        self._persist_capture_settings()
        self._emit_status()
        self.logger.info("Demo mode started.")
        return {
            "success": True,
            "mode": "demo",
            "message": self.message,
            "status": self.get_status(),
        }

    def stop_capture(self):
        with self.lock:
            thread_to_join = self._stop_locked(emit=False)
        self._join_demo_thread(thread_to_join)
        self._emit_status()
        self.logger.info("Capture stopped.")
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
        demo_thread = self.demo_thread
        self.demo_thread = None
        self.status = "stopped"
        self.message = "Capture stopped."
        self.last_error = ""
        self.last_failure_code = ""
        self.local_ips = self._collect_local_ips()
        if emit:
            self._emit_status()
        return demo_thread

    def _validate_live_start(self, requested_interface):
        if self.environment["hosted_mode"]:
            return {
                "ok": False,
                "code": "hosted_environment",
                "message": "Live capture unavailable in this hosted environment. Use demo mode for hosted deployments.",
            }

        if not self.environment["scapy_available"]:
            return {
                "ok": False,
                "code": "scapy_unavailable",
                "message": "Scapy is unavailable, so live capture cannot start. Install Scapy and packet capture dependencies or use demo mode.",
            }

        if platform.system().lower() == "windows" and not self.environment["windows_npcap_ready"]:
            return {
                "ok": False,
                "code": "npcap_required",
                "message": "Npcap is required for Windows live capture. Install Npcap with WinPcap compatibility if needed.",
            }

        interfaces = self.get_interfaces()
        usable_interfaces = [item for item in interfaces if item.get("usable")]
        if not usable_interfaces:
            return {
                "ok": False,
                "code": "no_usable_interface",
                "message": "No usable network interface detected for live capture.",
            }

        selected = requested_interface or self._choose_default_interface(usable_interfaces)
        if not selected:
            return {
                "ok": False,
                "code": "no_usable_interface",
                "message": "No usable network interface detected for live capture.",
            }

        available_names = {item["name"] for item in interfaces}
        if selected not in available_names:
            return {
                "ok": False,
                "code": "invalid_interface",
                "message": f"Selected interface '{selected}' is not available to Scapy on this system.",
                "interface": selected,
            }

        return {"ok": True, "interface": selected}

    def _choose_default_interface(self, interfaces):
        preferred = [
            item["name"]
            for item in interfaces
            if item.get("is_up") and item.get("ipv4") and not self._is_loopback(item["name"])
        ]
        if preferred:
            return preferred[0]

        non_loopback = [item["name"] for item in interfaces if not self._is_loopback(item["name"])]
        if non_loopback:
            return non_loopback[0]

        return interfaces[0]["name"] if interfaces else ""

    def _live_failure_response(self, code, message, selected_interface=""):
        with self.lock:
            self.status = "error"
            self.interface = selected_interface or self.interface or ""
            self.message = message
            self.last_error = message
            self.last_failure_code = code
        self._persist_capture_settings()
        self._emit_status()
        return {
            "success": False,
            "mode": "live",
            "message": message,
            "error_code": code,
            "status": self.get_status(),
        }

    def _classify_start_exception(self, exc):
        text = str(exc).lower()
        if "permission" in text or "not permitted" in text or "operation not permitted" in text:
            return "insufficient_permissions"
        if "interface" in text or "no such device" in text or "network adapter" in text:
            return "invalid_interface"
        if "pcap" in text or "npcap" in text or "winpcap" in text:
            return "npcap_required"
        return "capture_start_failed"

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

    def _join_demo_thread(self, thread):
        if thread and thread.is_alive():
            thread.join(timeout=1.0)

    def _is_loopback(self, name):
        return name.lower() in {"lo", "loopback", "lo0"}

    def _detect_windows_pcap_support(self):
        if conf is None:
            return False
        try:
            provider = getattr(conf, "use_pcap", None)
            if provider:
                return True
            sockets = getattr(conf, "L2listen", None)
            return sockets is not None
        except Exception:
            return False


def _timestamp_from_iso(value):
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return datetime.utcnow()
