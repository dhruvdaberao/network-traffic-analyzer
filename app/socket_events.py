from flask import current_app
from flask_socketio import emit

from . import socketio


def register_socket_events(app):
    @socketio.on("connect")
    def handle_connect():
        capture_service = current_app.extensions["capture_service"]
        stats_service = current_app.extensions["stats_service"]

        emit("capture_status", capture_service.get_status())
        emit("stats_update", stats_service.get_overview(capture_service.get_status()))
