"""Wireless ADB, Frida Server lifecycle, and device-readiness handlers."""

from __future__ import annotations

from pathlib import Path
import re
import subprocess
import tempfile
import threading
import time
import uuid

from flask import jsonify, request

from backend.common import json_file, strip_terminal_controls, token, truthy, utc_now
from backend.requests import DeviceReadinessRequest
from pipeline.frida_runtimes import frida_command, validate_frida_version
from worker.queue import atomic_write_json
from runtime_data import WIRELESS_DEVICES_PATH


_lock = threading.RLock()
_readiness: dict[str, dict] = {}


def endpoint_host(endpoint: str) -> str:
    value = endpoint.strip()
    if value.startswith("[") and "]" in value:
        return value[1:value.index("]")].lower()
    return value.rsplit(":", 1)[0].lower() if ":" in value else value.lower()


def wireless_registry() -> list[dict]:
    payload = json_file(WIRELESS_DEVICES_PATH) or {}
    devices = (payload.get("devices") or []) if isinstance(payload, dict) else []
    return [dict(item) for item in devices if isinstance(item, dict) and item.get("id")]


def record_wireless_device(*, pairing_endpoint: str = "", connection_endpoint: str = "", connected: bool = False) -> dict:
    """Persist non-secret host knowledge; pairing codes never enter this structure."""
    now = utc_now()
    host = endpoint_host(connection_endpoint or pairing_endpoint)
    with _lock:
        devices = wireless_registry()
        item = next((entry for entry in devices if any((
            connection_endpoint and entry.get("connection_endpoint") == connection_endpoint,
            pairing_endpoint and entry.get("pairing_endpoint") == pairing_endpoint,
            host and entry.get("host") == host,
        ))), None)
        if item is None:
            item = {"id": uuid.uuid4().hex, "host": host}
            devices.append(item)
        if pairing_endpoint:
            previous_pairing = str(item.get("pairing_endpoint") or "")
            if previous_pairing != pairing_endpoint:
                item.pop("connection_endpoint", None)
                item.pop("last_connected_utc", None)
            item["pairing_endpoint"] = pairing_endpoint
            item["paired_utc"] = now
        if connection_endpoint:
            item["connection_endpoint"] = connection_endpoint
        if connected:
            item["last_connected_utc"] = now
        item["updated_utc"] = now
        atomic_write_json(WIRELESS_DEVICES_PATH, {"devices": devices})
        return dict(item)


def discovered_mdns_services() -> list[dict]:
    try:
        result = subprocess.run(["adb", "mdns", "services"], text=True, capture_output=True, timeout=12)
    except (OSError, subprocess.TimeoutExpired):
        return []
    if result.returncode:
        return []
    services = []
    for line in result.stdout.splitlines():
        match = re.match(r"^\s*(\S+)\s+(_adb-tls-(pairing|connect)\._tcp)\s+(\S+:\d+)\s*$", line)
        if match:
            services.append({
                "name": match.group(1), "service": match.group(2),
                "kind": match.group(3), "endpoint": match.group(4),
            })
    return services


def wireless_device_view(found: list[dict], mdns: list[dict]) -> list[dict]:
    records = wireless_registry()
    live_by_serial = {item["serial"]: item for item in found}
    connect_services = [item for item in mdns if item["kind"] == "connect"]
    output: list[dict] = []
    represented: set[str] = set()
    for record in records:
        endpoint = str(record.get("connection_endpoint") or "")
        paired_utc = str(record.get("paired_utc") or "")
        last_connected_utc = str(record.get("last_connected_utc") or "")
        if paired_utc and paired_utc > last_connected_utc:
            endpoint = ""
        host = str(record.get("host") or endpoint_host(endpoint or str(record.get("pairing_endpoint") or "")))
        discovered = next((item for item in connect_services if endpoint_host(item["endpoint"]) == host), None)
        target = endpoint or str((discovered or {}).get("endpoint") or "")
        live = live_by_serial.get(target) or live_by_serial.get(endpoint)
        adb_state = str((live or {}).get("state") or "")
        status = "connected" if adb_state == "device" else adb_state if adb_state in {"offline", "unauthorized"} else "previously_paired"
        if target:
            represented.add(target)
        output.append({
            "id": record["id"], "host": host, "endpoint": target,
            "pairing_endpoint": str(record.get("pairing_endpoint") or ""),
            "status": status, "adb_state": adb_state, "paired": True,
            "discovered": bool(discovered), "connectable": bool(target and status != "connected"),
            "paired_utc": paired_utc, "last_connected_utc": last_connected_utc,
            "connection_required": not bool(target), "details": str((live or {}).get("details") or ""),
        })
    for live in found:
        serial = str(live["serial"])
        if serial in represented or not re.fullmatch(r"(?:\[[0-9a-fA-F:]+\]|[A-Za-z0-9._-]+):\d+", serial):
            continue
        output.append({
            "id": f"live-{serial}", "host": endpoint_host(serial), "endpoint": serial,
            "pairing_endpoint": "", "status": "connected" if live["state"] == "device" else live["state"],
            "adb_state": live["state"], "paired": False, "discovered": False,
            "connectable": live["state"] != "device", "paired_utc": "", "last_connected_utc": "",
            "details": live.get("details") or "",
        })
        represented.add(serial)
    for service in connect_services:
        endpoint = service["endpoint"]
        if endpoint in represented:
            continue
        output.append({
            "id": f"mdns-{service['name']}", "host": endpoint_host(endpoint), "endpoint": endpoint,
            "pairing_endpoint": "", "status": "discovered", "adb_state": "", "paired": False,
            "discovered": True, "connectable": True, "paired_utc": "", "last_connected_utc": "",
            "details": service["name"],
        })
    order = {"connected": 0, "unauthorized": 1, "offline": 2, "previously_paired": 3, "discovered": 4}
    return sorted(output, key=lambda item: (order.get(item["status"], 9), item.get("host") or ""))


def devices():
    result = subprocess.run(["adb", "devices", "-l"], text=True, capture_output=True, timeout=20)
    if result.returncode:
        raise ValueError(f"ADB discovery failed: {result.stderr or result.stdout}")
    found = []
    for line in result.stdout.splitlines():
        match = re.match(r"^([^\s]+)\s+(device|offline|unauthorized)(?:\s+(.*))?$", line)
        if match:
            found.append({"serial": match.group(1), "state": match.group(2), "details": match.group(3) or ""})
    mdns = discovered_mdns_services()
    return jsonify(devices=found, wireless_devices=wireless_device_view(found, mdns))


def connect_wireless_device():
    body = request.get_json(force=True, silent=False) or {}
    endpoint = token(str(body.get("endpoint") or ""), "wireless connection address", r"[A-Za-z0-9._:\-\[\]]+")
    result = subprocess.run(["adb", "connect", endpoint], text=True, capture_output=True, timeout=25)
    detail = strip_terminal_controls(result.stdout or result.stderr or "").strip()
    connected = result.returncode == 0 and bool(re.search(r"connected to|already connected", detail, re.I))
    if not connected:
        raise ValueError(f"Wireless ADB connection failed: {detail or 'No response from ADB.'}")
    record_wireless_device(connection_endpoint=endpoint, connected=True)
    return jsonify(connected=True, endpoint=endpoint, message="Wireless device connected.")


def adb_result(target: str, *arguments: str, timeout: int = 20) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["adb", "-s", target, *arguments], text=True, capture_output=True, timeout=timeout)


def parse_frida_server_processes(output: str, server_path: str) -> dict[int, str]:
    """Extract only recognizable Frida server processes from Android ps output."""
    processes: dict[int, str] = {}
    exact = server_path.lower()
    signature = re.compile(r"(?:^|[/\s])(?:frida-server[\w.-]*|re\.frida\.server)(?:\s|$)", re.I)
    for raw_line in output.splitlines():
        line = raw_line.strip()
        lowered = line.lower()
        if not line or (exact not in lowered and not signature.search(line)):
            continue
        fields = line.split()
        pid = next((int(field) for field in fields[:3] if field.isdigit()), None)
        if pid and pid > 1:
            processes[pid] = line
    return processes


def frida_server_processes(target: str, server_path: str) -> tuple[subprocess.CompletedProcess[str], dict[int, str]]:
    result = adb_result(target, "shell", "su", "-c", "ps -A -o PID,ARGS")
    return result, parse_frida_server_processes(result.stdout, server_path)


def readiness_check(name: str, passed: bool, detail: str, *, required: bool = True) -> dict:
    return {
        "name": name, "passed": bool(passed), "required": required,
        "detail": strip_terminal_controls(detail).strip()[-1200:],
    }


def replace_frida_server(target: str, server_path: str) -> tuple[list[dict], set[int]]:
    """Stop recognized Frida servers, start the selected path, and prove a new process survived."""
    checks: list[dict] = []
    inventory, existing = frida_server_processes(target, server_path)
    if inventory.returncode != 0:
        return [readiness_check(
            "Frida process inventory", False,
            inventory.stdout or inventory.stderr or "Android ps could not enumerate processes.",
        )], set()
    stopped: list[int] = []
    for pid in sorted(existing):
        killed = adb_result(target, "shell", "su", "-c", f"kill {pid}")
        if killed.returncode == 0:
            stopped.append(pid)
    stale = set(existing)
    for _ in range(6):
        time.sleep(0.25)
        _, remaining = frida_server_processes(target, server_path)
        stale = set(existing).intersection(remaining)
        if not stale:
            break
    force_stopped: list[int] = []
    if stale:
        for pid in sorted(stale):
            killed = adb_result(target, "shell", "su", "-c", f"kill -9 {pid}")
            if killed.returncode == 0:
                force_stopped.append(pid)
        for _ in range(6):
            time.sleep(0.25)
            _, remaining = frida_server_processes(target, server_path)
            stale = set(existing).intersection(remaining)
            if not stale:
                break
    stopped_detail = []
    if stopped:
        stopped_detail.append(f"Stopped recognized Frida PID(s): {', '.join(map(str, stopped))}.")
    if force_stopped:
        stopped_detail.append(f"Force-stopped PID(s) after SIGTERM timeout: {', '.join(map(str, force_stopped))}.")
    checks.append(readiness_check(
        "Previous Frida servers stopped", not stale,
        " ".join(stopped_detail) if not stale and stopped_detail
        else "No existing Frida server process was running." if not stale
        else f"Frida PID(s) still running after SIGKILL: {', '.join(map(str, sorted(stale)))}.",
    ))
    if stale:
        return checks, set()
    started = adb_result(target, "shell", "su", "-c", f"{server_path} -D >/dev/null 2>&1 &", timeout=20)
    checks.append(readiness_check(
        "Frida start command", started.returncode == 0,
        started.stdout or started.stderr or "Start command accepted.",
    ))
    if started.returncode != 0:
        return checks, set()
    live: dict[int, str] = {}
    for _ in range(6):
        time.sleep(0.5)
        process_result, live = frida_server_processes(target, server_path)
        if process_result.returncode == 0 and set(live).difference(existing):
            break
    new_pids = set(live).difference(existing)
    checks.append(readiness_check(
        "Frida server process", bool(new_pids),
        f"Selected server is running as PID(s): {', '.join(map(str, sorted(new_pids)))}."
        if new_pids else "The selected Frida Server exited before it became ready.",
    ))
    return checks, new_pids


def device_readiness():
    readiness_request = DeviceReadinessRequest(
        transport=str(request.form.get("transport") or ""), target=str(request.form.get("target") or ""),
        frida_server=str(request.form.get("frida_server") or ""),
        frida_version=str(request.form.get("frida_version") or ""),
        start_frida=truthy(request.form.get("start_frida")),
        authorized=truthy(request.form.get("authorized")),
    )
    transport = readiness_request.transport
    if transport not in {"adb", "wireless"}:
        raise ValueError("Invalid transport.")
    target = token(readiness_request.target, "device target", r"[A-Za-z0-9._:\-\[\]]+")
    frida_server = readiness_request.frida_server
    frida_version = validate_frida_version(readiness_request.frida_version)
    if frida_server:
        token(frida_server, "Frida Server path", r"/[A-Za-z0-9_./-]+")
    uploaded = request.files.get("frida_binary")
    start_frida = readiness_request.start_frida
    authorized = readiness_request.authorized
    if ((uploaded and uploaded.filename) or start_frida) and not authorized:
        raise ValueError("Confirm testing authorization before deploying or starting Frida Server.")
    checks: list[dict] = []
    if transport == "wireless":
        connected = subprocess.run(["adb", "connect", target], text=True, capture_output=True, timeout=25)
        wireless_ready = connected.returncode == 0 and bool(re.search(r"connected to|already connected", connected.stdout, re.I))
        checks.append(readiness_check("Wireless ADB", wireless_ready, connected.stdout or connected.stderr))
        if wireless_ready:
            record_wireless_device(connection_endpoint=target, connected=True)
    state = adb_result(target, "get-state")
    device_ready = state.returncode == 0 and state.stdout.strip() == "device"
    checks.append(readiness_check("ADB device", device_ready, state.stdout or state.stderr))
    if not device_ready:
        return jsonify(ready=False, target=target, transport=transport, checks=checks, token="")
    abi = adb_result(target, "shell", "getprop", "ro.product.cpu.abi")
    sdk = adb_result(target, "shell", "getprop", "ro.build.version.sdk")
    checks.append(readiness_check("Device ABI", abi.returncode == 0 and bool(abi.stdout.strip()), abi.stdout or abi.stderr))
    checks.append(readiness_check("Android SDK", sdk.returncode == 0 and sdk.stdout.strip().isdigit(), sdk.stdout or sdk.stderr))
    root = adb_result(target, "shell", "su", "-c", "id")
    checks.append(readiness_check("Root shell", root.returncode == 0 and "uid=0" in root.stdout, root.stdout or root.stderr))
    storage = adb_result(target, "shell", "df", "-k", "/data/local/tmp")
    checks.append(readiness_check("Temporary storage", storage.returncode == 0, storage.stdout or storage.stderr))
    selinux = adb_result(target, "shell", "getenforce")
    checks.append(readiness_check("SELinux", selinux.returncode == 0, selinux.stdout or selinux.stderr, required=False))
    temporary_path: Path | None = None
    try:
        if uploaded and uploaded.filename:
            if not frida_server:
                raise ValueError("Enter a device-side Frida Server path before deploying a binary.")
            with tempfile.NamedTemporaryFile(prefix="mob-ai-frida-", delete=False) as temporary:
                temporary_path = Path(temporary.name)
                uploaded.save(temporary)
            if temporary_path.stat().st_size < 1024:
                raise ValueError("The selected Frida Server binary is unexpectedly small.")
            pushed = subprocess.run(
                ["adb", "-s", target, "push", str(temporary_path), frida_server],
                text=True, capture_output=True, timeout=120,
            )
            checks.append(readiness_check("Frida deployment", pushed.returncode == 0, pushed.stdout or pushed.stderr))
            if pushed.returncode == 0:
                chmod = adb_result(target, "shell", "su", "-c", f"chmod 755 {frida_server}")
                checks.append(readiness_check("Frida executable", chmod.returncode == 0, chmod.stdout or chmod.stderr or frida_server))
        frida_start_ready = not start_frida
        host_version = subprocess.run(
            [*frida_command(frida_version, "frida"), "--version"], text=True, capture_output=True, timeout=15,
        )
        checks.append(readiness_check("Frida client", host_version.returncode == 0, host_version.stdout or host_version.stderr))
        if frida_server:
            executable = adb_result(target, "shell", "su", "-c", f"test -x {frida_server}")
            checks.append(readiness_check("Frida Server path", executable.returncode == 0, frida_server if executable.returncode == 0 else executable.stdout or executable.stderr or "Missing or not executable"))
            server_version = adb_result(target, "shell", "su", "-c", f"{frida_server} --version", timeout=30)
            server_text = (server_version.stdout or server_version.stderr).strip()
            versions_match = host_version.returncode == 0 and server_version.returncode == 0 and host_version.stdout.strip() == server_text
            checks.append(readiness_check(
                "Frida version match", versions_match,
                f"client {host_version.stdout.strip() or 'unknown'} / server {server_text or 'unknown'}",
            ))
            if start_frida and executable.returncode == 0 and versions_match:
                process_checks, _active_pids = replace_frida_server(target, frida_server)
                checks.extend(process_checks)
                frida_start_ready = all(check["passed"] for check in process_checks if check["required"])
        if frida_start_ready:
            forwarded = adb_result(target, "forward", "tcp:27042", "tcp:27042")
            checks.append(readiness_check("Frida port forwarding", forwarded.returncode == 0, forwarded.stdout or forwarded.stderr))
            frida_probe = subprocess.CompletedProcess([], 1, "", "Frida connection was not attempted.")
            for _ in range(4):
                frida_probe = subprocess.run(
                    [*frida_command(frida_version, "frida-ps"), "-H", "127.0.0.1:27042"],
                    text=True, capture_output=True, timeout=20,
                )
                if frida_probe.returncode == 0:
                    break
                time.sleep(0.5)
            checks.append(readiness_check("Frida connection", frida_probe.returncode == 0, frida_probe.stdout or frida_probe.stderr))
        else:
            checks.append(readiness_check(
                "Frida connection", False, "Skipped because the selected Frida Server was not replaced successfully.",
            ))
    finally:
        if temporary_path:
            temporary_path.unlink(missing_ok=True)
    ready = all(check["passed"] for check in checks if check["required"])
    readiness_token = ""
    if ready:
        readiness_token = uuid.uuid4().hex
        with _lock:
            now = time.monotonic()
            _readiness.clear()
            _readiness[readiness_token] = {
                "target": target, "transport": transport, "frida_server": frida_server,
                "frida_version": frida_version, "created": now, "expires": now + 600,
            }
    return jsonify(
        ready=ready, target=target, transport=transport, abi=abi.stdout.strip(), sdk=sdk.stdout.strip(),
        frida_version=frida_version, checks=checks, token=readiness_token,
    )


def pair_wireless_device():
    body = request.get_json(force=True, silent=False) or {}
    endpoint = token(str(body.get("endpoint") or ""), "pairing address", r"[A-Za-z0-9._:\-\[\]]+")
    pairing_code = str(body.get("code") or "")
    if not re.fullmatch(r"[0-9]{6}", pairing_code):
        raise ValueError("Wireless pairing code must contain exactly six digits.")
    try:
        result = subprocess.run(
            ["adb", "pair", endpoint], input=pairing_code + "\n", text=True, capture_output=True, timeout=45,
        )
        if result.returncode:
            detail = (result.stderr or result.stdout or "ADB pairing failed.").strip()
            detail = re.sub(r"(?i):\s*success\s*$", "", detail).rstrip()
            detail = detail.replace(pairing_code, "******")[-1000:]
            raise ValueError(f"Wireless pairing failed: {detail}")
    except subprocess.TimeoutExpired as error:
        raise ValueError("Wireless pairing timed out. Confirm the pairing address and try again.") from error
    finally:
        pairing_code = ""
    matching_connections = [
        service["endpoint"] for service in discovered_mdns_services()
        if service["kind"] == "connect" and endpoint_host(service["endpoint"]) == endpoint_host(endpoint)
    ]
    connection_endpoint = matching_connections[0] if len(matching_connections) == 1 else ""
    record_wireless_device(pairing_endpoint=endpoint, connection_endpoint=connection_endpoint)
    return jsonify(
        paired=True, endpoint=endpoint, connection_endpoint=connection_endpoint,
        message="Wireless debugging paired successfully.",
    )
