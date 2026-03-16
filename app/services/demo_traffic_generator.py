import random
import time
from datetime import datetime


class DemoTrafficGenerator:
    def __init__(self, callback, stop_event, interval_seconds=0.55):
        self.callback = callback
        self.stop_event = stop_event
        self.interval_seconds = interval_seconds
        self.local_client = "192.168.1.23"
        self.gateway = "192.168.1.1"
        self.web_hosts = [
            ("93.184.216.34", "example.com"),
            ("142.250.183.14", "www.google.com"),
            ("151.101.1.69", "cdn.jsdelivr.net"),
        ]
        self.index = 0

    def run(self):
        scenarios = [
            self._normal_web_browsing,
            self._https_traffic,
            self._dns_queries,
            self._file_download_burst,
            self._icmp_sequence,
            self._port_scan_event,
            self._repeated_dns_pattern,
        ]

        while not self.stop_event.is_set():
            scenario = scenarios[self.index % len(scenarios)]
            for packet in scenario():
                if self.stop_event.is_set():
                    break
                self.callback(packet)
                time.sleep(self.interval_seconds)
            self.index += 1

    def _packet(self, **kwargs):
        base = {
            "timestamp": datetime.utcnow(),
            "src_ip": self.local_client,
            "dst_ip": self.gateway,
            "src_port": random.randint(40000, 60000),
            "dst_port": None,
            "protocol": "TCP",
            "length": random.randint(60, 300),
            "tcp_flags": "",
            "dns_query": "",
            "http_host": "",
            "http_method": "",
            "summary": "",
        }
        base.update(kwargs)
        return base

    def _normal_web_browsing(self):
        server_ip, host = random.choice(self.web_hosts)
        return [
            self._packet(
                dst_ip="8.8.8.8",
                dst_port=53,
                protocol="DNS",
                length=78,
                dns_query=host,
                summary=f"DNS lookup for {host}",
            ),
            self._packet(
                dst_ip=server_ip,
                dst_port=80,
                protocol="HTTP",
                length=512,
                http_host=host,
                http_method="GET",
                summary=f"HTTP GET / on {host}",
            ),
            self._packet(
                src_ip=server_ip,
                dst_ip=self.local_client,
                src_port=80,
                dst_port=random.randint(40000, 60000),
                protocol="HTTP",
                length=924,
                summary=f"HTTP 200 response from {host}",
            ),
        ]

    def _https_traffic(self):
        server_ip, host = random.choice(self.web_hosts)
        return [
            self._packet(
                dst_ip=server_ip,
                dst_port=443,
                protocol="HTTPS/TLS",
                length=128,
                tcp_flags="S",
                summary=f"TLS handshake start to {host}",
            ),
            self._packet(
                src_ip=server_ip,
                dst_ip=self.local_client,
                src_port=443,
                dst_port=random.randint(40000, 60000),
                protocol="HTTPS/TLS",
                length=420,
                summary=f"TLS application traffic from {host}",
            ),
            self._packet(
                dst_ip=server_ip,
                dst_port=443,
                protocol="HTTPS/TLS",
                length=640,
                summary=f"Encrypted application data to {host}",
            ),
        ]

    def _dns_queries(self):
        domains = ["github.com", "openai.com", "python.org"]
        return [
            self._packet(
                dst_ip="1.1.1.1",
                dst_port=53,
                protocol="DNS",
                length=74,
                dns_query=domain,
                summary=f"DNS query for {domain}",
            )
            for domain in domains
        ]

    def _file_download_burst(self):
        server_ip = "198.51.100.20"
        return [
            self._packet(
                dst_ip=server_ip,
                dst_port=443,
                protocol="HTTPS/TLS",
                length=1450,
                summary="Large HTTPS download segment",
            )
            for _ in range(10)
        ]

    def _icmp_sequence(self):
        return [
            self._packet(
                dst_ip="10.0.0.5",
                protocol="ICMP",
                length=98,
                src_port=None,
                dst_port=None,
                summary="ICMP echo request to 10.0.0.5",
            )
            for _ in range(6)
        ]

    def _port_scan_event(self):
        attacker = "203.0.113.45"
        target = self.local_client
        ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 3389]
        return [
            self._packet(
                src_ip=attacker,
                dst_ip=target,
                src_port=random.randint(30000, 60000),
                dst_port=port,
                protocol="TCP",
                tcp_flags="S",
                length=64,
                summary=f"SYN probe from {attacker} to port {port}",
            )
            for port in ports
        ]

    def _repeated_dns_pattern(self):
        noisy_host = "198.18.0.77"
        query = "suspicious.internal"
        return [
            self._packet(
                src_ip=noisy_host,
                dst_ip="8.8.4.4",
                src_port=random.randint(40000, 65000),
                dst_port=53,
                protocol="DNS",
                length=82,
                dns_query=query,
                summary=f"Repeated DNS lookup for {query}",
            )
            for _ in range(10)
        ]
