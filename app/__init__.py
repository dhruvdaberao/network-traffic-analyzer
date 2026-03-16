import logging
from pathlib import Path

from flask import Flask
from flask_socketio import SocketIO
from flask_sqlalchemy import SQLAlchemy

from config import Config


db = SQLAlchemy()
socketio = SocketIO(async_mode="threading", cors_allowed_origins="*")


def create_app(config_class=Config):
    app = Flask(
        __name__,
        instance_path=str(Path(__file__).resolve().parent.parent / "instance"),
        instance_relative_config=True,
    )
    app.config.from_object(config_class)

    Path(app.instance_path).mkdir(parents=True, exist_ok=True)
    _configure_logging(app)

    db.init_app(app)
    socketio.init_app(app)

    from . import models  # noqa: F401

    with app.app_context():
        db.create_all()
        _ensure_default_settings()

    from .routes import main_bp
    from .services.capture_service import CaptureService
    from .services.detection_engine import DetectionEngine
    from .services.stats_service import StatsService
    from .socket_events import register_socket_events

    stats_service = StatsService(app, socketio)
    detection_engine = DetectionEngine(app, socketio, stats_service)
    capture_service = CaptureService(app, socketio, stats_service, detection_engine)

    app.extensions["stats_service"] = stats_service
    app.extensions["detection_engine"] = detection_engine
    app.extensions["capture_service"] = capture_service

    app.register_blueprint(main_bp)
    register_socket_events(app)

    if app.config.get("HOSTED_MODE") and app.config.get("AUTO_START_DEMO"):
        capture_service.start_demo(
            "Hosted environment detected. Demo mode started automatically."
        )

    return app


def _configure_logging(app):
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    app.logger.setLevel(logging.INFO)


def _ensure_default_settings():
    from .models import AppSetting

    defaults = {
        "capture_mode": "demo",
        "capture_interface": "",
    }
    for key, value in defaults.items():
        existing = AppSetting.query.filter_by(key=key).first()
        if not existing:
            db.session.add(AppSetting(key=key, value=value))
    db.session.commit()
