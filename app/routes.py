from flask import Blueprint, current_app, jsonify, render_template, request
from sqlalchemy import or_

from .models import AlertLog, PacketLog, TrafficSnapshot, db
from .services.export_service import export_alerts_csv, export_packets_csv


main_bp = Blueprint("main", __name__)


def _services():
    return (
        current_app.extensions["capture_service"],
        current_app.extensions["stats_service"],
        current_app.extensions["detection_engine"],
    )


@main_bp.route("/")
def index():
    return render_template("index.html", active_page="overview")


@main_bp.route("/live")
def live():
    return render_template("live.html", active_page="live")


@main_bp.route("/alerts")
def alerts():
    return render_template("alerts.html", active_page="alerts")


@main_bp.route("/packets")
def packets():
    return render_template(
        "packets.html",
        active_page="packets",
        default_page_size=current_app.config["DEFAULT_PACKET_PAGE_SIZE"],
    )


@main_bp.route("/settings")
def settings():
    capture_service, _, detection_engine = _services()
    return render_template(
        "settings.html",
        active_page="settings",
        capture_state=capture_service.get_status(),
        interfaces=capture_service.get_interfaces(),
        thresholds=detection_engine.get_thresholds(),
    )


@main_bp.get("/api/overview")
def api_overview():
    capture_service, stats_service, _ = _services()
    return jsonify(stats_service.get_overview(capture_service.get_status()))


@main_bp.get("/api/traffic/protocol-distribution")
def api_protocol_distribution():
    _, stats_service, _ = _services()
    return jsonify({"items": stats_service.get_protocol_distribution()})


@main_bp.get("/api/traffic/bandwidth")
def api_bandwidth():
    _, stats_service, _ = _services()
    return jsonify(stats_service.get_timeseries())


@main_bp.get("/api/traffic/top-talkers")
def api_top_talkers():
    _, stats_service, _ = _services()
    return jsonify(stats_service.get_top_talkers())


@main_bp.get("/api/packets")
def api_packets():
    page = max(int(request.args.get("page", 1)), 1)
    per_page = min(int(request.args.get("per_page", 25)), 100)
    protocol = request.args.get("protocol", "").strip()
    src_ip = request.args.get("src_ip", "").strip()
    dst_ip = request.args.get("dst_ip", "").strip()
    search = request.args.get("search", "").strip()

    query = PacketLog.query.order_by(PacketLog.timestamp.desc())

    if protocol and protocol.lower() != "all":
        query = query.filter(PacketLog.protocol.ilike(protocol))
    if src_ip:
        query = query.filter(PacketLog.src_ip.ilike(f"%{src_ip}%"))
    if dst_ip:
        query = query.filter(PacketLog.dst_ip.ilike(f"%{dst_ip}%"))
    if search:
        like = f"%{search}%"
        query = query.filter(
            or_(
                PacketLog.summary.ilike(like),
                PacketLog.dns_query.ilike(like),
                PacketLog.http_host.ilike(like),
            )
        )

    pagination = query.paginate(page=page, per_page=per_page, error_out=False)

    return jsonify(
        {
            "items": [item.to_dict() for item in pagination.items],
            "pagination": {
                "page": pagination.page,
                "pages": pagination.pages,
                "per_page": per_page,
                "total": pagination.total,
                "has_next": pagination.has_next,
                "has_prev": pagination.has_prev,
            },
        }
    )


@main_bp.get("/api/alerts")
def api_alerts():
    limit = min(int(request.args.get("limit", 100)), 200)
    status = request.args.get("status", "").strip()
    query = AlertLog.query.order_by(AlertLog.timestamp.desc())
    if status and status.lower() != "all":
        query = query.filter(AlertLog.status == status)
    alerts = query.limit(limit).all()
    return jsonify({"items": [alert.to_dict() for alert in alerts]})


@main_bp.post("/api/alerts/<int:alert_id>/review")
def api_review_alert(alert_id):
    capture_service, stats_service, _ = _services()
    alert = AlertLog.query.get_or_404(alert_id)
    if alert.status != "Reviewed":
        alert.status = "Reviewed"
        db.session.commit()
        stats_service.mark_alert_reviewed()
        current_app.extensions["stats_service"].socketio.emit(
            "stats_update", stats_service.get_overview(capture_service.get_status())
        )
    return jsonify({"success": True, "item": alert.to_dict()})


@main_bp.post("/api/capture/start")
def api_capture_start():
    capture_service, _, _ = _services()
    payload = request.get_json(silent=True) or {}
    result = capture_service.start_live(payload.get("interface"))
    return jsonify(result)


@main_bp.post("/api/capture/demo-start")
def api_capture_demo_start():
    capture_service, _, _ = _services()
    return jsonify(capture_service.start_demo())


@main_bp.post("/api/capture/stop")
def api_capture_stop():
    capture_service, _, _ = _services()
    return jsonify(capture_service.stop_capture())


@main_bp.get("/api/interfaces")
def api_interfaces():
    capture_service, _, _ = _services()
    return jsonify(
        {
            "items": capture_service.get_interfaces(),
            "selected": capture_service.get_status().get("interface"),
        }
    )


@main_bp.get("/api/settings/current")
def api_settings_current():
    capture_service, _, detection_engine = _services()
    return jsonify(
        {
            "capture_state": capture_service.get_status(),
            "thresholds": detection_engine.get_thresholds(),
            "interfaces": capture_service.get_interfaces(),
        }
    )


@main_bp.post("/api/settings/thresholds")
def api_settings_thresholds():
    _, _, detection_engine = _services()
    payload = request.get_json(silent=True) or {}
    return jsonify(detection_engine.update_thresholds(payload))


@main_bp.post("/api/settings/clear-data")
def api_settings_clear_data():
    capture_service, stats_service, detection_engine = _services()
    capture_service.stop_capture()

    PacketLog.query.delete()
    AlertLog.query.delete()
    TrafficSnapshot.query.delete()
    db.session.commit()

    stats_service.reset_state()
    detection_engine.reset_state()
    current_app.extensions["stats_service"].socketio.emit(
        "stats_update", stats_service.get_overview(capture_service.get_status())
    )
    return jsonify({"success": True, "message": "Captured data cleared."})


@main_bp.get("/api/export/alerts")
def api_export_alerts():
    return export_alerts_csv()


@main_bp.get("/api/export/packets")
def api_export_packets():
    return export_packets_csv()
