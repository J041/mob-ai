"""Flask Blueprint registration grouped by API responsibility."""

from .auth import create_auth_blueprint
from .devices import create_devices_blueprint
from .jobs import create_jobs_blueprint
from .runs import create_runs_blueprint
from .system import create_system_blueprint

__all__ = [
    "create_auth_blueprint", "create_devices_blueprint", "create_jobs_blueprint",
    "create_runs_blueprint", "create_system_blueprint",
]
