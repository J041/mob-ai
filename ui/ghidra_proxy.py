from __future__ import annotations

import os
import socket
import socketserver
import threading
from urllib.parse import urlsplit


class _RelayServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, address: tuple[str, int], upstream: tuple[str, int]):
        self.upstream = upstream
        super().__init__(address, _RelayHandler)


class _RelayHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        with socket.create_connection(self.server.upstream, timeout=10) as upstream:  # type: ignore[attr-defined]
            client = self.request

            def relay(source: socket.socket, destination: socket.socket) -> None:
                try:
                    while True:
                        block = source.recv(64 * 1024)
                        if not block:
                            break
                        destination.sendall(block)
                except (ConnectionError, OSError):
                    pass
                finally:
                    try:
                        destination.shutdown(socket.SHUT_WR)
                    except OSError:
                        pass

            outbound = threading.Thread(
                target=relay, args=(client, upstream), name="ghidra-proxy-upload", daemon=True,
            )
            outbound.start()
            relay(upstream, client)
            outbound.join(timeout=2)


class GhidraLoopbackProxy:
    """Expose the private Compose Ghidra service on worker loopback for its MCP bridge."""

    def __init__(self, upstream_url: str, *, port: int | None = None):
        parsed = urlsplit(upstream_url)
        if parsed.scheme != "http" or not parsed.hostname or parsed.port is None:
            raise ValueError("GHIDRA_MCP_URL must be an HTTP URL with an explicit host and port.")
        if parsed.path not in {"", "/"} or parsed.query or parsed.fragment or parsed.username:
            raise ValueError("GHIDRA_MCP_URL must not contain credentials, a path, query, or fragment.")
        configured_port = int(os.environ.get("MOB_AI_GHIDRA_PROXY_PORT", "18089")) if port is None else port
        self._server = _RelayServer(("127.0.0.1", configured_port), (parsed.hostname, parsed.port))
        self._thread = threading.Thread(
            target=self._server.serve_forever, name="ghidra-loopback-proxy", daemon=True,
        )

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self._server.server_address[1]}"

    def start(self) -> GhidraLoopbackProxy:
        self._thread.start()
        return self

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=5)

