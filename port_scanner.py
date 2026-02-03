#!/usr/bin/env python3
import argparse
import csv
import ipaddress
import json
import socket
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, Iterable, List, Optional, Tuple


TOOL_NAME = "Simple Port Scanner"
__version__ = "2.0.0-dev"


COMMON_PORTS = [
    20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 110, 111, 119, 123, 135, 137,
    138, 139, 143, 161, 162, 179, 389, 443, 445, 465, 514, 515, 587, 636,
    993, 995, 1080, 1194, 1433, 1434, 1521, 2049, 2082, 2083, 2086, 2087,
    2095, 2096, 2181, 2375, 2376, 2483, 2484, 3000, 3306, 3389, 3690, 4000,
    4040, 4443, 4567, 5000, 5001, 5060, 5432, 5672, 5900, 5984, 5985, 5986,
    6379, 6443, 6667, 7001, 7002, 7199, 7474, 7547, 8000, 8008, 8009, 8080,
    8081, 8086, 8087, 8090, 8181, 8333, 8443, 8500, 853, 854, 8600, 8888,
    9000, 9090, 9200, 9300, 9443, 9999, 11211, 27017,
]

TOP20_PORTS = [
    20, 21, 22, 23, 25, 53, 80, 110, 111, 135,
    139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900,
]

ALLOWED_CONFIG_KEYS = {
    "host",
    "ports",
    "common",
    "top20",
    "timeout",
    "workers",
    "sequential",
    "delay",
    "service",
    "open_only",
    "output",
    "format",
    "no_color",
    "no_progress",
}

DEFAULTS = {
    "timeout": 0.5,
    "workers": 100,
    "delay": 0.0,
    "format": "auto",
    "sequential": False,
    "service": False,
    "open_only": False,
    "no_color": False,
    "no_progress": False,
    "common": False,
    "top20": False,
}


class ConfigError(RuntimeError):
    pass


@dataclass
class Settings:
    host: str
    ports: Optional[str]
    common: bool
    top20: bool
    timeout: float
    workers: int
    sequential: bool
    delay: float
    service: bool
    open_only: bool
    output: Optional[str]
    format: str
    no_color: bool
    no_progress: bool


def parse_ports(ports_str: str) -> List[int]:
    ports: List[int] = []
    for part in ports_str.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start_s, end_s = part.split("-", 1)
            start = int(start_s)
            end = int(end_s)
            if start > end:
                start, end = end, start
            ports.extend(range(start, end + 1))
        else:
            ports.append(int(part))
    # Deduplicate while preserving order
    seen = set()
    unique_ports = []
    for p in ports:
        if 1 <= p <= 65535 and p not in seen:
            seen.add(p)
            unique_ports.append(p)
    return unique_ports


def colorize(text: str, code: str, enable: bool) -> str:
    if not enable:
        return text
    return f"\033[{code}m{text}\033[0m"


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def normalize_ports_value(value: Any) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, list):
        return ",".join(str(item) for item in value)
    return str(value)


def load_config(path: str) -> Dict[str, Any]:
    if path.lower().endswith((".yaml", ".yml")):
        try:
            import yaml  # type: ignore
        except ImportError as exc:
            raise ConfigError(
                "YAML config requested but PyYAML is not installed. "
                "Install with: pip install pyyaml"
            ) from exc
        with open(path, "r", encoding="utf-8") as handle:
            data = yaml.safe_load(handle)
    else:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)

    if data is None:
        return {}
    if not isinstance(data, dict):
        raise ConfigError("Config file must contain a JSON/YAML object at top level.")

    unknown = set(data.keys()) - ALLOWED_CONFIG_KEYS
    if unknown:
        unknown_list = ", ".join(sorted(unknown))
        raise ConfigError(f"Unknown config keys: {unknown_list}")

    return data


def merge_settings(args: argparse.Namespace, config: Dict[str, Any]) -> Settings:
    def pick(name: str, default: Any = None) -> Any:
        cli_value = getattr(args, name)
        if cli_value is not None:
            return cli_value
        if name in config:
            return config[name]
        return default

    def pick_bool(name: str, default: bool) -> bool:
        cli_value = getattr(args, name)
        if cli_value is not None:
            return bool(cli_value)
        if name in config:
            return bool(config[name])
        return default

    host = pick("host")
    if not host:
        raise ConfigError("Host is required (use --host or set host in config).")

    ports_cli = args.ports
    common_cli = args.common
    top20_cli = args.top20
    selection_cli_set = any(value is not None for value in (ports_cli, common_cli, top20_cli))

    ports_config = normalize_ports_value(config.get("ports")) if "ports" in config else None
    common_config = bool(config.get("common")) if "common" in config else None
    top20_config = bool(config.get("top20")) if "top20" in config else None

    if selection_cli_set:
        ports_value = ports_cli if ports_cli is not None else None
        common_value = bool(common_cli) if common_cli is not None else False
        top20_value = bool(top20_cli) if top20_cli is not None else False
    else:
        ports_value = ports_config
        common_value = bool(common_config) if common_config is not None else DEFAULTS["common"]
        top20_value = bool(top20_config) if top20_config is not None else DEFAULTS["top20"]

    settings = Settings(
        host=host,
        ports=ports_value,
        common=common_value,
        top20=top20_value,
        timeout=float(pick("timeout", DEFAULTS["timeout"])),
        workers=int(pick("workers", DEFAULTS["workers"])),
        sequential=pick_bool("sequential", DEFAULTS["sequential"]),
        delay=float(pick("delay", DEFAULTS["delay"])),
        service=pick_bool("service", DEFAULTS["service"]),
        open_only=pick_bool("open_only", DEFAULTS["open_only"]),
        output=pick("output"),
        format=str(pick("format", DEFAULTS["format"])),
        no_color=pick_bool("no_color", DEFAULTS["no_color"]),
        no_progress=pick_bool("no_progress", DEFAULTS["no_progress"]),
    )

    selection_count = sum(
        [
            1 if settings.ports else 0,
            1 if settings.common else 0,
            1 if settings.top20 else 0,
        ]
    )
    if selection_count == 0:
        raise ConfigError(
            "Port selection is required (use --ports/--common/--top20 or set in config)."
        )
    if selection_count > 1:
        raise ConfigError("Choose only one of ports, common, or top20.")

    if settings.format not in {"auto", "text", "json", "csv"}:
        raise ConfigError("Format must be one of: auto, text, json, csv.")

    return settings


def should_show_progress(disabled: bool) -> bool:
    return sys.stdout.isatty() and not disabled


def render_progress(done: int, total: int, started: float) -> None:
    if total <= 0:
        return
    percent = (done / total) * 100
    bar_len = 20
    filled = int(bar_len * done / total)
    bar = "#" * filled + "-" * (bar_len - filled)
    elapsed = time.monotonic() - started
    line = f"\rProgress: [{bar}] {done}/{total} ({percent:.0f}%) Elapsed: {elapsed:.1f}s"
    print(line, end="", flush=True)


def resolve_host(host: str) -> str:
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        return socket.gethostbyname(host)


def scan_port(host: str, port: int, timeout: float) -> Tuple[int, bool]:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        return port, result == 0


def guess_service(port: int) -> str:
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return ""


def write_output(
    path: str,
    fmt: str,
    target_host: str,
    target_ip: str,
    started_at: str,
    ended_at: str,
    tool_version: str,
    results: List[Dict[str, object]],
    scanned_total: int,
    open_total: int,
    duration_s: float,
) -> None:
    if fmt == "auto":
        if path.lower().endswith(".json"):
            fmt = "json"
        elif path.lower().endswith(".csv"):
            fmt = "csv"
        else:
            fmt = "text"

    if fmt == "json":
        payload = {
            "tool": {"name": TOOL_NAME, "version": tool_version},
            "target": {"host": target_host, "ip": target_ip},
            "started_at": started_at,
            "ended_at": ended_at,
            "scanned_ports": scanned_total,
            "open_ports": open_total,
            "duration_seconds": round(duration_s, 4),
            "results": results,
        }
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2)
        return

    if fmt == "csv":
        with open(path, "w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(
                handle,
                fieldnames=["port", "open", "service", "scanned_at"],
            )
            writer.writeheader()
            for row in results:
                writer.writerow(
                    {
                        "port": row["port"],
                        "open": row["open"],
                        "service": row.get("service", ""),
                        "scanned_at": started_at,
                    }
                )
        return

    with open(path, "w", encoding="utf-8") as handle:
        handle.write(f"Tool: {TOOL_NAME} {tool_version}\n")
        handle.write(f"Target: {target_host} ({target_ip})\n")
        handle.write(f"Started: {started_at}\n")
        handle.write(f"Ended: {ended_at}\n")
        handle.write(f"Scanned: {scanned_total} | Open: {open_total}\n")
        handle.write("\n")
        for row in results:
            status = "open" if row["open"] else "closed"
            service = row.get("service") or ""
            if service:
                handle.write(f"{row['port']}/tcp {status} ({service})\n")
            else:
                handle.write(f"{row['port']}/tcp {status}\n")


def main(argv: Iterable[str]) -> int:
    parser = argparse.ArgumentParser(
        description="Simple TCP port scanner (educational)."
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument(
        "--config",
        help="Path to JSON/YAML config file",
    )
    parser.add_argument("--host", required=False, help="Target hostname or IP")
    ports_group = parser.add_mutually_exclusive_group(required=False)
    ports_group.add_argument(
        "--ports",
        help="Port list/range, e.g. 22,80,443 or 8000-8100",
        default=None,
    )
    ports_group.add_argument(
        "--common",
        action="store_true",
        help="Scan a curated list of common ports",
        default=None,
    )
    ports_group.add_argument(
        "--top20",
        action="store_true",
        help="Scan a short list of the top 20 common ports",
        default=None,
    )
    parser.add_argument("--timeout", type=float, default=None, help="Socket timeout (s)")
    parser.add_argument(
        "--workers",
        type=int,
        default=None,
        help="Max concurrent connections",
    )
    parser.add_argument(
        "--sequential",
        action="store_true",
        help="Scan sequentially (ignores --workers)",
        default=None,
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=None,
        help="Delay between scheduling ports (s)",
    )
    parser.add_argument(
        "--service",
        action="store_true",
        help="Try to guess service names for open ports",
        default=None,
    )
    parser.add_argument(
        "--open-only",
        action="store_true",
        help="Only include open ports in file output",
        default=None,
    )
    parser.add_argument(
        "--output",
        help="Write results to a file (text, .json, or .csv)",
    )
    parser.add_argument(
        "--format",
        choices=["auto", "text", "json", "csv"],
        default=None,
        help="Output format for --output (default: auto by extension)",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable colored output",
        default=None,
    )
    parser.add_argument(
        "--no-progress",
        action="store_true",
        help="Disable progress indicator",
        default=None,
    )

    args = parser.parse_args(list(argv))

    config: Dict[str, Any] = {}
    if args.config:
        try:
            config = load_config(args.config)
        except ConfigError as exc:
            print(f"Config error: {exc}", file=sys.stderr)
            return 2
        except (OSError, json.JSONDecodeError) as exc:
            print(f"Failed to load config: {exc}", file=sys.stderr)
            return 2

    try:
        settings = merge_settings(args, config)
    except ConfigError as exc:
        print(f"Config error: {exc}", file=sys.stderr)
        return 2

    try:
        target_ip = resolve_host(settings.host)
    except socket.gaierror as exc:
        print(f"Failed to resolve host: {exc}", file=sys.stderr)
        return 2

    if settings.common or settings.top20:
        source = TOP20_PORTS if settings.top20 else COMMON_PORTS
        seen = set()
        ports = []
        for p in source:
            if 1 <= p <= 65535 and p not in seen:
                seen.add(p)
                ports.append(p)
    else:
        ports = parse_ports(settings.ports or "")
    if not ports:
        print("No valid ports provided.", file=sys.stderr)
        return 2

    color_enabled = sys.stdout.isatty() and not settings.no_color
    show_progress = should_show_progress(settings.no_progress)

    if settings.sequential:
        settings.workers = 1

    started = time.monotonic()
    started_at = utc_now_iso()
    port_min = min(ports)
    port_max = max(ports)
    print(colorize("Target:", "36", color_enabled), f"{settings.host} ({target_ip})")
    print(
        colorize("Ports:", "36", color_enabled),
        f"{port_min}..{port_max} ({len(ports)} total)",
    )
    print(
        colorize("Timeout:", "36", color_enabled),
        f"{settings.timeout}s | Workers: {settings.workers}",
    )
    if settings.delay > 0:
        print(colorize("Schedule delay:", "36", color_enabled), f"{settings.delay}s")
    print()

    total_ports = len(ports)
    open_ports: List[int] = []
    results: List[Dict[str, object]] = []
    if settings.sequential:
        done = 0
        for port in ports:
            port_num, is_open = scan_port(target_ip, port, settings.timeout)
            if is_open:
                open_ports.append(port_num)
            if settings.delay > 0:
                time.sleep(settings.delay)
            done += 1
            if show_progress:
                render_progress(done, total_ports, started)
    else:
        with ThreadPoolExecutor(max_workers=settings.workers) as executor:
            futures = []
            for port in ports:
                futures.append(
                    executor.submit(scan_port, target_ip, port, settings.timeout)
                )
                if settings.delay > 0:
                    time.sleep(settings.delay)

            done = 0
            last_update = started
            for future in as_completed(futures):
                port_num, is_open = future.result()
                if is_open:
                    open_ports.append(port_num)
                done += 1
                now = time.monotonic()
                if show_progress and (done == total_ports or (now - last_update) >= 0.1):
                    render_progress(done, total_ports, started)
                    last_update = now

    open_set = set(open_ports)
    for port in sorted(ports):
        is_open = port in open_set
        service = guess_service(port) if (is_open and settings.service) else ""
        results.append({"port": port, "open": is_open, "service": service})

    if show_progress:
        print()

    ended = time.monotonic()
    ended_at = utc_now_iso()
    duration_s = ended - started

    open_ports = [row["port"] for row in results if row["open"]]
    open_total = len(open_ports)

    output_rows = results
    if settings.open_only:
        output_rows = [row for row in results if row["open"]]

    if not open_ports:
        print(colorize("No open ports found.", "33", color_enabled))
        print()
        print(colorize("Summary:", "36", color_enabled))
        print(f"Scanned: {len(ports)} | Open: 0 | Closed: {len(ports)}")
        print(f"Duration: {duration_s:.3f}s")
        if settings.output:
            write_output(
                settings.output,
                settings.format,
                settings.host,
                target_ip,
                started_at,
                ended_at,
                __version__,
                output_rows,
                len(ports),
                open_total,
                duration_s,
            )
            print(colorize("Saved:", "32", color_enabled), settings.output)
        return 0

    print(colorize("Open ports:", "32", color_enabled))
    for row in results:
        if not row["open"]:
            continue
        service = row.get("service") or ""
        if service:
            print(f"- {row['port']}/tcp ({service})")
        else:
            print(f"- {row['port']}/tcp")

    print()
    print(colorize("Summary:", "36", color_enabled))
    print(
        f"Scanned: {len(ports)} | Open: {len(open_ports)} | Closed: {len(ports) - len(open_ports)}"
    )
    print(f"Duration: {duration_s:.3f}s")

    if settings.output:
        write_output(
            settings.output,
            settings.format,
            settings.host,
            target_ip,
            started_at,
            ended_at,
            __version__,
            output_rows,
            len(ports),
            open_total,
            duration_s,
        )
        print(colorize("Saved:", "32", color_enabled), settings.output)

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
