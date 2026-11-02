from __future__ import annotations

from flask import Blueprint


def create_devices_blueprint(handlers) -> Blueprint:
    blueprint = Blueprint("devices", __name__)
    blueprint.add_url_rule("/api/devices", view_func=handlers.devices, methods=["GET"])
    blueprint.add_url_rule("/api/devices/connect", view_func=handlers.connect_wireless_device, methods=["POST"])
    blueprint.add_url_rule("/api/devices/readiness", view_func=handlers.device_readiness, methods=["POST"])
    blueprint.add_url_rule("/api/devices/pair", view_func=handlers.pair_wireless_device, methods=["POST"])
    return blueprint
