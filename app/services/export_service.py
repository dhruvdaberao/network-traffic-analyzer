import csv
import io
from datetime import datetime

from flask import Response

from ..models import AlertLog, PacketLog


def export_alerts_csv():
    headers = [
        "id",
        "timestamp",
        "alert_type",
        "severity",
        "src_ip",
        "dst_ip",
        "reason",
        "metric_value",
        "threshold_value",
        "status",
    ]
    rows = [
        [
            alert.id,
            alert.timestamp.isoformat(),
            alert.alert_type,
            alert.severity,
            alert.src_ip or "",
            alert.dst_ip or "",
            alert.reason,
            alert.metric_value or "",
            alert.threshold_value or "",
            alert.status,
        ]
        for alert in AlertLog.query.order_by(AlertLog.timestamp.desc()).all()
    ]
    return _csv_response("alerts", headers, rows)


def export_packets_csv():
    headers = [
        "id",
        "timestamp",
        "src_ip",
        "dst_ip",
        "src_port",
        "dst_port",
        "protocol",
        "length",
        "tcp_flags",
        "dns_query",
        "http_host",
        "http_method",
        "direction",
        "summary",
    ]
    rows = [
        [
            packet.id,
            packet.timestamp.isoformat(),
            packet.src_ip or "",
            packet.dst_ip or "",
            packet.src_port or "",
            packet.dst_port or "",
            packet.protocol or "",
            packet.length or 0,
            packet.tcp_flags or "",
            packet.dns_query or "",
            packet.http_host or "",
            packet.http_method or "",
            packet.direction or "",
            packet.summary,
        ]
        for packet in PacketLog.query.order_by(PacketLog.timestamp.desc()).all()
    ]
    return _csv_response("packets", headers, rows)


def _csv_response(prefix, headers, rows):
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(headers)
    writer.writerows(rows)
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    filename = f"{prefix}_{timestamp}.csv"
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )
