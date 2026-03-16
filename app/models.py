from datetime import datetime

from . import db


class PacketLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True, nullable=False)
    src_ip = db.Column(db.String(64), index=True)
    dst_ip = db.Column(db.String(64), index=True)
    src_port = db.Column(db.Integer)
    dst_port = db.Column(db.Integer)
    protocol = db.Column(db.String(32), index=True)
    length = db.Column(db.Integer, default=0)
    tcp_flags = db.Column(db.String(32))
    dns_query = db.Column(db.String(255))
    http_host = db.Column(db.String(255))
    http_method = db.Column(db.String(32))
    direction = db.Column(db.String(32))
    summary = db.Column(db.Text, nullable=False)

    def to_dict(self):
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat(),
            "src_ip": self.src_ip or "-",
            "dst_ip": self.dst_ip or "-",
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol or "Unknown",
            "length": self.length or 0,
            "tcp_flags": self.tcp_flags or "",
            "dns_query": self.dns_query or "",
            "http_host": self.http_host or "",
            "http_method": self.http_method or "",
            "direction": self.direction or "unknown",
            "summary": self.summary,
        }


class AlertLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True, nullable=False)
    src_ip = db.Column(db.String(64), index=True)
    dst_ip = db.Column(db.String(64), index=True)
    alert_type = db.Column(db.String(64), index=True, nullable=False)
    severity = db.Column(db.String(16), index=True, nullable=False)
    reason = db.Column(db.Text, nullable=False)
    metric_value = db.Column(db.Float)
    threshold_value = db.Column(db.Float)
    status = db.Column(db.String(16), default="New", index=True, nullable=False)

    def to_dict(self):
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat(),
            "src_ip": self.src_ip or "-",
            "dst_ip": self.dst_ip or "-",
            "alert_type": self.alert_type,
            "severity": self.severity,
            "reason": self.reason,
            "metric_value": self.metric_value,
            "threshold_value": self.threshold_value,
            "status": self.status,
        }


class TrafficSnapshot(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True, nullable=False)
    total_packets = db.Column(db.Integer, default=0)
    total_bytes = db.Column(db.Integer, default=0)
    bandwidth_bps = db.Column(db.Float, default=0.0)
    dominant_protocol = db.Column(db.String(32))
    active_alerts = db.Column(db.Integer, default=0)

    def to_dict(self):
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat(),
            "total_packets": self.total_packets,
            "total_bytes": self.total_bytes,
            "bandwidth_bps": self.bandwidth_bps,
            "dominant_protocol": self.dominant_protocol or "Unknown",
            "active_alerts": self.active_alerts,
        }


class AppSetting(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(100), unique=True, nullable=False)
    value = db.Column(db.Text, nullable=False)

    @classmethod
    def get_value(cls, key, default=None):
        record = cls.query.filter_by(key=key).first()
        return record.value if record else default

    @classmethod
    def set_value(cls, key, value):
        record = cls.query.filter_by(key=key).first()
        if not record:
            record = cls(key=key, value=value)
            db.session.add(record)
        else:
            record.value = value
        db.session.commit()
