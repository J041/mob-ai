from __future__ import annotations

from flask import Blueprint


def create_auth_blueprint(handlers) -> Blueprint:
    blueprint = Blueprint("auth", __name__)
    blueprint.add_url_rule("/api/providers/<provider>/auth", view_func=handlers.get_provider_auth, methods=["GET"])
    blueprint.add_url_rule("/api/providers/<provider>/auth/login", view_func=handlers.begin_provider_auth, methods=["POST"])
    blueprint.add_url_rule("/api/providers/<provider>/auth/logout", view_func=handlers.logout_provider_auth, methods=["POST"])
    blueprint.add_url_rule("/api/auth", view_func=handlers.get_auth, methods=["GET"])
    blueprint.add_url_rule("/api/auth/device", view_func=handlers.begin_auth, methods=["POST"])
    blueprint.add_url_rule("/api/auth/logout", view_func=handlers.logout_auth, methods=["POST"])
    return blueprint
