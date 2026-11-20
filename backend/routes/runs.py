from __future__ import annotations

from flask import Blueprint


def create_runs_blueprint(handlers) -> Blueprint:
    blueprint = Blueprint("runs", __name__)
    blueprint.add_url_rule("/api/runs", view_func=handlers.list_runs, methods=["GET"])
    blueprint.add_url_rule("/api/runs/<run_id>", view_func=handlers.delete_run, methods=["DELETE"])
    blueprint.add_url_rule("/api/runs/<run_id>/artifacts", view_func=handlers.list_run_artifacts, methods=["GET"])
    blueprint.add_url_rule("/api/runs/<run_id>/artifacts/content", view_func=handlers.preview_run_artifact, methods=["GET"])
    blueprint.add_url_rule("/api/runs/<run_id>/artifacts/download", view_func=handlers.download_run_artifact, methods=["GET"])
    blueprint.add_url_rule("/api/runs/<run_id>/assistant", view_func=handlers.get_run_assistant, methods=["GET"])
    blueprint.add_url_rule("/api/runs/<run_id>/assistant", view_func=handlers.ask_run_assistant, methods=["POST"])
    blueprint.add_url_rule("/api/runs/<run_id>/assistant/requests/<request_id>", view_func=handlers.get_run_assistant_request, methods=["GET"])
    blueprint.add_url_rule("/api/runs/<run_id>/deep-investigation", view_func=handlers.start_deep_investigation, methods=["POST"])
    blueprint.add_url_rule("/api/runs/<run_id>/launch-bypass", view_func=handlers.start_bypass_launch, methods=["POST"])
    return blueprint
