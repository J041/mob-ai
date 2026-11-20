from __future__ import annotations

from flask import Blueprint


def create_system_blueprint(handlers) -> Blueprint:
    blueprint = Blueprint("system", __name__)
    blueprint.add_url_rule("/api/health", view_func=handlers.health, methods=["GET"])
    blueprint.add_url_rule("/api/overview", view_func=handlers.overview, methods=["GET"])
    blueprint.add_url_rule("/api/events", view_func=handlers.events, methods=["GET"])
    blueprint.add_url_rule("/api/models", view_func=handlers.models, methods=["GET"])
    blueprint.add_url_rule("/api/providers", view_func=handlers.providers, methods=["GET"])
    blueprint.add_url_rule("/api/apks", view_func=handlers.upload_apk, methods=["POST"])
    blueprint.add_url_rule("/api/policies/preview", view_func=handlers.preview_success_policy, methods=["GET"])
    blueprint.add_url_rule("/api/policies", view_func=handlers.save_success_policy, methods=["POST"])
    return blueprint
