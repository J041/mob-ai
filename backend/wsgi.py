"""Production entrypoint that prepares portable runtime storage before Flask starts."""

from runtime_data import initialize_runtime_data


initialize_runtime_data()

from backend.app import app  # noqa: E402  (storage must exist before app imports)
