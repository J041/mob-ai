from __future__ import annotations

from flask import Blueprint


def create_jobs_blueprint(handlers) -> Blueprint:
    blueprint = Blueprint("jobs", __name__)
    blueprint.add_url_rule("/api/jobs", view_func=handlers.list_jobs, methods=["GET"])
    blueprint.add_url_rule("/api/jobs/<job_id>", view_func=handlers.get_job, methods=["GET"])
    blueprint.add_url_rule("/api/start", view_func=handlers.start, methods=["POST"])
    blueprint.add_url_rule("/api/resume", view_func=handlers.resume, methods=["POST"])
    blueprint.add_url_rule("/api/retry", view_func=handlers.retry, methods=["POST"])
    return blueprint
