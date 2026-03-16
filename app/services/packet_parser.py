from datetime import datetime

try:
    from scapy.layers.dns import DNS, DNSQR
    from scapy.layers.inet import ICMP, IP, TCP, UDP
    from scapy.layers.l2 import ARP
    from scapy.packet import Raw
except Exception:  # pragma: no cover
    ARP = DNS = DNSQR = ICMP = IP = Raw = TCP = UDP = None


HTTP_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}


def parse_packet(packet, local_ips=None):
    if isinstance(packet, dict):
        return _normalize_demo_packet(packet, local_ips or set())
    return _parse_scapy_packet(packet, local_ips or set())


def _parse_scapy_packet(packet, local_ips):
    data = _blank_packet()
    data["timestamp"] = _safe_timestamp(getattr(packet, "time", None))

    try:
        if ARP and packet.haslayer(ARP):
            arp = packet[ARP]
            data.update(
                {
                    "src_ip": getattr(arp, "psrc", None),
                    "dst_ip": getattr(arp, "pdst", None),
                    "protocol": "ARP",
                    "length": len(packet),
                    "summary": f"ARP {getattr(arp, 'psrc', '-')} -> {getattr(arp, 'pdst', '-')}",
                }
            )
            data["direction"] = _infer_direction(data["src_ip"], data["dst_ip"], local_ips)
            return data

        if IP and packet.haslayer(IP):
            ip_layer = packet[IP]
            data["src_ip"] = getattr(ip_layer, "src", None)
            data["dst_ip"] = getattr(ip_layer, "dst", None)
            data["length"] = int(getattr(ip_layer, "len", len(packet) or 0))

        if TCP and packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            data["src_port"] = getattr(tcp_layer, "sport", None)
            data["dst_port"] = getattr(tcp_layer, "dport", None)
            data["tcp_flags"] = str(getattr(tcp_layer, "flags", ""))
            data["protocol"] = _classify_transport("TCP", data["src_port"], data["dst_port"])

            if Raw and packet.haslayer(Raw):
                data.update(_extract_http_metadata(bytes(packet[Raw].load), data))
        elif UDP and packet.haslayer(UDP):
            udp_layer = packet[UDP]
            data["src_port"] = getattr(udp_layer, "sport", None)
            data["dst_port"] = getattr(udp_layer, "dport", None)
            data["protocol"] = _classify_transport("UDP", data["src_port"], data["dst_port"])
        elif ICMP and packet.haslayer(ICMP):
            data["protocol"] = "ICMP"

        if DNS and packet.haslayer(DNS):
            data["protocol"] = "DNS"
            if packet.haslayer(DNSQR):
                dns_query = getattr(packet[DNSQR], "qname", b"")
                if isinstance(dns_query, bytes):
                    dns_query = dns_query.decode(errors="ignore")
                data["dns_query"] = (dns_query or "").rstrip(".")

        data["protocol"] = data["protocol"] or "Other"
        data["direction"] = _infer_direction(data["src_ip"], data["dst_ip"], local_ips)
        data["summary"] = data["summary"] or _build_summary(data)
        return data
    except Exception:
        data["protocol"] = data["protocol"] or "Unknown"
        data["summary"] = data["summary"] or "Malformed or unsupported packet"
        data["direction"] = _infer_direction(data["src_ip"], data["dst_ip"], local_ips)
        return data


def _normalize_demo_packet(packet, local_ips):
    data = _blank_packet()
    data.update(packet)
    data["timestamp"] = _safe_timestamp(packet.get("timestamp"))
    data["protocol"] = packet.get("protocol") or _classify_transport(
        packet.get("transport"),
        packet.get("src_port"),
        packet.get("dst_port"),
    )
    data["direction"] = packet.get("direction") or _infer_direction(
        packet.get("src_ip"),
        packet.get("dst_ip"),
        local_ips,
    )
    data["summary"] = packet.get("summary") or _build_summary(data)
    data["dns_query"] = packet.get("dns_query", "")
    data["http_host"] = packet.get("http_host", "")
    data["http_method"] = packet.get("http_method", "")
    return data


def _classify_transport(base_protocol, src_port, dst_port):
    ports = {src_port, dst_port}
    if 53 in ports:
        return "DNS"
    if 80 in ports or 8080 in ports:
        return "HTTP"
    if 443 in ports or 8443 in ports:
        return "HTTPS/TLS"
    if base_protocol == "TCP":
        return "TCP"
    if base_protocol == "UDP":
        return "UDP"
    return "Other"


def _extract_http_metadata(payload, data):
    result = {}
    text = payload.decode("utf-8", errors="ignore")
    lines = text.split("\r\n")
    if not lines:
        return result

    first_line = lines[0].split()
    if len(first_line) >= 2 and first_line[0] in HTTP_METHODS:
        result["protocol"] = "HTTP"
        result["http_method"] = first_line[0]
        path = first_line[1]
        for line in lines[1:12]:
            if line.lower().startswith("host:"):
                result["http_host"] = line.split(":", 1)[1].strip()
                break
        result["summary"] = (
            f"HTTP {result.get('http_method', '')} {path} "
            f"{result.get('http_host', data.get('dst_ip', '-'))}".strip()
        )
    return result


def _infer_direction(src_ip, dst_ip, local_ips):
    if not src_ip and not dst_ip:
        return "unknown"
    if src_ip in local_ips:
        return "outbound"
    if dst_ip in local_ips:
        return "inbound"
    return "external"


def _build_summary(data):
    protocol = data.get("protocol") or "Unknown"
    src = data.get("src_ip") or "-"
    dst = data.get("dst_ip") or "-"
    src_port = f":{data['src_port']}" if data.get("src_port") else ""
    dst_port = f":{data['dst_port']}" if data.get("dst_port") else ""
    extra = []

    if data.get("dns_query"):
        extra.append(data["dns_query"])
    if data.get("http_method"):
        extra.append(data["http_method"])
    if data.get("tcp_flags"):
        extra.append(f"flags={data['tcp_flags']}")

    suffix = f" ({', '.join(extra)})" if extra else ""
    return f"{protocol} {src}{src_port} -> {dst}{dst_port}{suffix}"


def _blank_packet():
    return {
        "timestamp": datetime.utcnow(),
        "src_ip": None,
        "dst_ip": None,
        "src_port": None,
        "dst_port": None,
        "protocol": None,
        "length": 0,
        "tcp_flags": "",
        "dns_query": "",
        "http_host": "",
        "http_method": "",
        "direction": "unknown",
        "summary": "",
    }


def _safe_timestamp(value):
    if isinstance(value, datetime):
        return value
    if isinstance(value, (int, float)):
        try:
            return datetime.fromtimestamp(value)
        except (OSError, OverflowError, ValueError):
            return datetime.utcnow()
    return datetime.utcnow()
