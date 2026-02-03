#!/usr/bin/env python3
import argparse
import asyncio
import csv
import errno
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
__version__ = "2.0.0.dev0"


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
    "hosts",
    "host_file",
    "cidr",
    "range",
    "max_hosts",
    "engine",
    "profile",
    "ports",
    "common",
    "top20",
    "timeout",
    "workers",
    "sequential",
    "delay",
    "retries",
    "retry_delay",
    "retry_backoff",
    "retry_on",
    "banner",
    "banner_bytes",
    "banner_timeout",
    "service",
    "open_only",
    "output",
    "format",
    "no_color",
    "no_progress",
}

DEFAULTS = {
    "engine": "async",
    "timeout": 0.5,
    "workers": 100,
    "delay": 0.0,
    "format": "auto",
    "max_hosts": 1024,
    "retries": 0,
    "retry_delay": 0.1,
    "retry_backoff": 2.0,
    "retry_on": "transient",
    "banner": False,
    "banner_bytes": 512,
    "banner_timeout": 0.3,
    "sequential": False,
    "service": False,
    "open_only": False,
    "no_color": False,
    "no_progress": False,
    "common": False,
    "top20": False,
}

RATE_PROFILES = {
    "stealth": {
        "workers": 10,
        "delay": 0.1,
        "timeout": 1.0,
        "retries": 1,
        "retry_delay": 0.2,
        "retry_backoff": 2.0,
        "retry_on": "transient",
    },
    "polite": {
        "workers": 50,
        "delay": 0.02,
        "timeout": 0.7,
        "retries": 1,
        "retry_delay": 0.1,
        "retry_backoff": 2.0,
        "retry_on": "transient",
    },
    "normal": {
        "workers": 100,
        "delay": 0.0,
        "timeout": 0.5,
        "retries": 0,
        "retry_delay": 0.1,
        "retry_backoff": 2.0,
        "retry_on": "transient",
    },
    "fast": {
        "workers": 300,
        "delay": 0.0,
        "timeout": 0.3,
        "retries": 0,
        "retry_delay": 0.05,
        "retry_backoff": 2.0,
        "retry_on": "transient",
    },
}


class ConfigError(RuntimeError):
    pass


@dataclass
class Settings:
    host: Optional[str]
    hosts: Optional[str]
    host_file: Optional[str]
    cidr: Optional[str]
    host_range: Optional[str]
    max_hosts: int
    engine: str
    profile: Optional[str]
    ports: Optional[str]
    common: bool
    top20: bool
    timeout: float
    workers: int
    sequential: bool
    delay: float
    retries: int
    retry_delay: float
    retry_backoff: float
    retry_on: str
    banner: bool
    banner_bytes: int
    banner_timeout: float
    service: bool
    open_only: bool
    output: Optional[str]
    format: str
    no_color: bool
    no_progress: bool


@dataclass
class TargetInfo:
    host: str
    ip: str
    family: int


@dataclass
class TargetScanResult:
    target: TargetInfo
    results: List[Dict[str, object]]
    open_total: int
    scanned_total: int
    duration_s: float


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


def normalize_hosts_value(value: Any) -> Optional[str]:
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

    profile_cli = args.profile
    profile_config = config.get("profile") if "profile" in config else None
    profile = profile_cli if profile_cli is not None else profile_config
    base_defaults = dict(DEFAULTS)
    if profile:
        if profile not in RATE_PROFILES:
            raise ConfigError(
                f"Unknown profile: {profile}. Choose from: {', '.join(sorted(RATE_PROFILES))}."
            )
        base_defaults.update(RATE_PROFILES[profile])

    targets_cli = {
        "host": args.host,
        "hosts": args.hosts,
        "host_file": args.host_file,
        "cidr": args.cidr,
        "host_range": args.range,
    }
    targets_cli_set = any(value is not None for value in targets_cli.values())

    if targets_cli_set:
        host = args.host
        hosts = args.hosts
        host_file = args.host_file
        cidr = args.cidr
        host_range = args.range
    else:
        host = config.get("host")
        hosts = normalize_hosts_value(config.get("hosts")) if "hosts" in config else None
        host_file = config.get("host_file")
        cidr = config.get("cidr")
        host_range = config.get("range")

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
        hosts=hosts,
        host_file=host_file,
        cidr=cidr,
        host_range=host_range,
        max_hosts=int(pick("max_hosts", base_defaults["max_hosts"])),
        engine=str(pick("engine", base_defaults["engine"])),
        profile=profile,
        ports=ports_value,
        common=common_value,
        top20=top20_value,
        timeout=float(pick("timeout", base_defaults["timeout"])),
        workers=int(pick("workers", base_defaults["workers"])),
        sequential=pick_bool("sequential", base_defaults["sequential"]),
        delay=float(pick("delay", base_defaults["delay"])),
        retries=int(pick("retries", base_defaults["retries"])),
        retry_delay=float(pick("retry_delay", base_defaults["retry_delay"])),
        retry_backoff=float(pick("retry_backoff", base_defaults["retry_backoff"])),
        retry_on=str(pick("retry_on", base_defaults["retry_on"])),
        banner=pick_bool("banner", base_defaults["banner"]),
        banner_bytes=int(pick("banner_bytes", base_defaults["banner_bytes"])),
        banner_timeout=float(pick("banner_timeout", base_defaults["banner_timeout"])),
        service=pick_bool("service", base_defaults["service"]),
        open_only=pick_bool("open_only", base_defaults["open_only"]),
        output=pick("output"),
        format=str(pick("format", base_defaults["format"])),
        no_color=pick_bool("no_color", base_defaults["no_color"]),
        no_progress=pick_bool("no_progress", base_defaults["no_progress"]),
    )

    if settings.max_hosts < 1:
        raise ConfigError("max_hosts must be at least 1.")
    if settings.engine not in {"async", "thread"}:
        raise ConfigError("engine must be either 'async' or 'thread'.")
    if settings.retries < 0:
        raise ConfigError("retries must be 0 or greater.")
    if settings.retry_delay < 0:
        raise ConfigError("retry_delay must be 0 or greater.")
    if settings.retry_backoff < 1:
        raise ConfigError("retry_backoff must be 1 or greater.")
    if settings.retry_on not in {"transient", "timeout", "any"}:
        raise ConfigError("retry_on must be one of: transient, timeout, any.")
    if settings.banner_bytes < 1 or settings.banner_bytes > 8192:
        raise ConfigError("banner_bytes must be between 1 and 8192.")
    if settings.banner_timeout < 0:
        raise ConfigError("banner_timeout must be 0 or greater.")

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


def parse_host_list(value: str) -> List[str]:
    parts = [item.strip() for item in value.split(",")]
    return [item for item in parts if item]


def load_hosts_from_file(path: str) -> List[str]:
    hosts: List[str] = []
    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            cleaned = line.strip()
            if not cleaned or cleaned.startswith("#"):
                continue
            hosts.append(cleaned)
    return hosts


def expand_cidr(value: str, remaining: int) -> List[str]:
    network = ipaddress.ip_network(value, strict=False)
    host_count = network.num_addresses
    if network.version == 4 and host_count > 2:
        host_count -= 2
    if host_count > remaining:
        raise ConfigError(
            f"CIDR expands to {host_count} hosts, which exceeds the remaining limit "
            f"of {remaining}. Increase --max-hosts to proceed."
        )
    return [str(ip) for ip in network.hosts()]


def expand_ip_range(value: str, remaining: int) -> List[str]:
    if "-" not in value:
        raise ConfigError("IP range must use start-end format, e.g. 192.168.1.10-192.168.1.50")
    start_s, end_s = value.split("-", 1)
    start = ipaddress.ip_address(start_s.strip())
    end = ipaddress.ip_address(end_s.strip())
    if start.version != end.version:
        raise ConfigError("IP range start/end must use the same IP version.")
    if int(start) > int(end):
        start, end = end, start
    count = int(end) - int(start) + 1
    if count > remaining:
        raise ConfigError(
            f"IP range expands to {count} hosts, which exceeds the remaining limit "
            f"of {remaining}. Increase --max-hosts to proceed."
        )
    return [str(ipaddress.ip_address(value)) for value in range(int(start), int(end) + 1)]


def collect_targets(settings: Settings) -> List[str]:
    targets: List[str] = []
    seen = set()

    def add(items: Iterable[str]) -> None:
        for item in items:
            if item and item not in seen:
                targets.append(item)
                seen.add(item)

    if settings.host:
        add([settings.host])
    if settings.hosts:
        add(parse_host_list(settings.hosts))
    if settings.host_file:
        add(load_hosts_from_file(settings.host_file))
    if settings.cidr:
        remaining = settings.max_hosts - len(targets)
        if remaining <= 0:
            raise ConfigError("Target limit reached. Increase --max-hosts to add CIDR.")
        add(expand_cidr(settings.cidr, remaining))
    if settings.host_range:
        remaining = settings.max_hosts - len(targets)
        if remaining <= 0:
            raise ConfigError("Target limit reached. Increase --max-hosts to add range.")
        add(expand_ip_range(settings.host_range, remaining))

    if not targets:
        raise ConfigError(
            "Target selection is required (use --host/--hosts/--host-file/--cidr/--range or set in config)."
        )
    if len(targets) > settings.max_hosts:
        raise ConfigError(
            f"Target count {len(targets)} exceeds max_hosts {settings.max_hosts}. "
            "Increase --max-hosts to proceed."
        )
    return targets


def resolve_target(host: str) -> TargetInfo:
    try:
        ip_value = ipaddress.ip_address(host)
        family = socket.AF_INET6 if ip_value.version == 6 else socket.AF_INET
        return TargetInfo(host=host, ip=str(ip_value), family=family)
    except ValueError:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
        for family, _socktype, _proto, _canon, sockaddr in infos:
            if family == socket.AF_INET:
                return TargetInfo(host=host, ip=sockaddr[0], family=family)
        for family, _socktype, _proto, _canon, sockaddr in infos:
            if family == socket.AF_INET6:
                return TargetInfo(host=host, ip=sockaddr[0], family=family)
        raise socket.gaierror(f"Unable to resolve host: {host}")


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


def address_for_family(ip: str, port: int, family: int) -> Tuple:
    if family == socket.AF_INET6:
        return (ip, port, 0, 0)
    return (ip, port)

def connect_once(ip: str, port: int, timeout: float, family: int) -> int:
    with socket.socket(family, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        return sock.connect_ex(address_for_family(ip, port, family))


def should_retry(error_code: int, retry_on: str) -> bool:
    if retry_on == "any":
        return True
    if retry_on == "timeout":
        return error_code == errno.ETIMEDOUT
    if retry_on == "transient":
        return error_code in {
            errno.ETIMEDOUT,
            errno.EHOSTUNREACH,
            errno.ENETUNREACH,
            errno.ECONNRESET,
            errno.ECONNABORTED,
            errno.EADDRNOTAVAIL,
        }
    return False


def scan_port_with_retries(
    ip: str,
    port: int,
    timeout: float,
    family: int,
    retries: int,
    retry_delay: float,
    retry_backoff: float,
    retry_on: str,
) -> Tuple[int, bool]:
    delay = retry_delay
    for attempt in range(retries + 1):
        code = connect_once(ip, port, timeout, family)
        if code == 0:
            return port, True
        if attempt >= retries or not should_retry(code, retry_on):
            return port, False
        if delay > 0:
            time.sleep(delay)
        delay *= retry_backoff
    return port, False


def decode_banner_bytes(data: bytes) -> str:
    if not data:
        return ""
    text = data.decode("utf-8", errors="replace")
    text = text.replace("\r", "\\r").replace("\n", "\\n")
    return text.strip()


def grab_banner(
    ip: str,
    port: int,
    family: int,
    timeout: float,
    max_bytes: int,
) -> str:
    try:
        with socket.socket(family, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            code = sock.connect_ex(address_for_family(ip, port, family))
            if code != 0:
                return ""
            try:
                data = sock.recv(max_bytes)
            except socket.timeout:
                return ""
            except OSError:
                return ""
    except OSError:
        return ""

    return decode_banner_bytes(data)


async def async_connect_socket(
    ip: str,
    port: int,
    family: int,
    timeout: float,
) -> Tuple[int, Optional[socket.socket]]:
    loop = asyncio.get_running_loop()
    sock = socket.socket(family, socket.SOCK_STREAM)
    sock.setblocking(False)
    try:
        await asyncio.wait_for(
            loop.sock_connect(sock, address_for_family(ip, port, family)),
            timeout=timeout,
        )
        return 0, sock
    except asyncio.TimeoutError:
        sock.close()
        return errno.ETIMEDOUT, None
    except OSError as exc:
        code = exc.errno or errno.ECONNREFUSED
        sock.close()
        return code, None


async def async_read_banner(
    sock: socket.socket,
    timeout: float,
    max_bytes: int,
) -> bytes:
    loop = asyncio.get_running_loop()
    try:
        data = await asyncio.wait_for(loop.sock_recv(sock, max_bytes), timeout=timeout)
        return data
    except asyncio.TimeoutError:
        return b""
    except OSError:
        return b""


async def async_scan_port_with_retries(
    ip: str,
    port: int,
    timeout: float,
    family: int,
    retries: int,
    retry_delay: float,
    retry_backoff: float,
    retry_on: str,
    banner_enabled: bool,
    banner_timeout: float,
    banner_bytes: int,
) -> Tuple[int, bool, str]:
    delay = retry_delay
    for attempt in range(retries + 1):
        code, sock = await async_connect_socket(ip, port, family, timeout)
        if code == 0 and sock:
            banner = ""
            try:
                if banner_enabled:
                    data = await async_read_banner(sock, banner_timeout, banner_bytes)
                    banner = decode_banner_bytes(data)
            finally:
                sock.close()
            return port, True, banner
        if attempt >= retries or not should_retry(code, retry_on):
            return port, False, ""
        if delay > 0:
            await asyncio.sleep(delay)
        delay *= retry_backoff
    return port, False, ""


def format_banner_preview(value: str, max_len: int = 120) -> str:
    if len(value) <= max_len:
        return value
    return value[: max_len - 1] + "…"


def guess_service(port: int) -> str:
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return ""


def scan_ports_for_target_thread(
    target: TargetInfo,
    ports: List[int],
    settings: Settings,
    show_progress: bool,
) -> TargetScanResult:
    started = time.monotonic()
    total_ports = len(ports)
    open_ports: List[int] = []
    results: List[Dict[str, object]] = []

    if settings.sequential:
        done = 0
        for port in ports:
            port_num, is_open = scan_port_with_retries(
                target.ip,
                port,
                settings.timeout,
                target.family,
                settings.retries,
                settings.retry_delay,
                settings.retry_backoff,
                settings.retry_on,
            )
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
                    executor.submit(
                        scan_port_with_retries,
                        target.ip,
                        port,
                        settings.timeout,
                        target.family,
                        settings.retries,
                        settings.retry_delay,
                        settings.retry_backoff,
                        settings.retry_on,
                    )
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
        banner = ""
        if is_open and settings.banner:
            banner = grab_banner(
                target.ip,
                port,
                target.family,
                settings.banner_timeout,
                settings.banner_bytes,
            )
        results.append(
            {
                "port": port,
                "open": is_open,
                "service": service,
                "banner": banner,
            }
        )

    if show_progress:
        print()

    duration_s = time.monotonic() - started
    open_total = sum(1 for row in results if row["open"])
    return TargetScanResult(
        target=target,
        results=results,
        open_total=open_total,
        scanned_total=total_ports,
        duration_s=duration_s,
    )


async def scan_ports_for_target_async(
    target: TargetInfo,
    ports: List[int],
    settings: Settings,
    show_progress: bool,
) -> TargetScanResult:
    started = time.monotonic()
    total_ports = len(ports)
    results_map: Dict[int, Tuple[bool, str]] = {}
    semaphore = asyncio.Semaphore(settings.workers)

    async def run_port(port: int) -> Tuple[int, bool, str]:
        async with semaphore:
            return await async_scan_port_with_retries(
                target.ip,
                port,
                settings.timeout,
                target.family,
                settings.retries,
                settings.retry_delay,
                settings.retry_backoff,
                settings.retry_on,
                settings.banner,
                settings.banner_timeout,
                settings.banner_bytes,
            )

    tasks = []
    for port in ports:
        tasks.append(asyncio.create_task(run_port(port)))
        if settings.delay > 0:
            await asyncio.sleep(settings.delay)

    done = 0
    last_update = started
    for task in asyncio.as_completed(tasks):
        port_num, is_open, banner = await task
        results_map[port_num] = (is_open, banner)
        done += 1
        now = time.monotonic()
        if show_progress and (done == total_ports or (now - last_update) >= 0.1):
            render_progress(done, total_ports, started)
            last_update = now

    if show_progress:
        print()

    results: List[Dict[str, object]] = []
    for port in sorted(ports):
        is_open, banner = results_map.get(port, (False, ""))
        service = guess_service(port) if (is_open and settings.service) else ""
        results.append(
            {
                "port": port,
                "open": is_open,
                "service": service,
                "banner": banner,
            }
        )

    duration_s = time.monotonic() - started
    open_total = sum(1 for row in results if row["open"])
    return TargetScanResult(
        target=target,
        results=results,
        open_total=open_total,
        scanned_total=total_ports,
        duration_s=duration_s,
    )


def scan_ports_for_target(
    target: TargetInfo,
    ports: List[int],
    settings: Settings,
    show_progress: bool,
) -> TargetScanResult:
    if settings.engine == "thread":
        return scan_ports_for_target_thread(target, ports, settings, show_progress)
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(
            scan_ports_for_target_async(target, ports, settings, show_progress)
        )
    return scan_ports_for_target_thread(target, ports, settings, show_progress)


def write_output(
    path: str,
    fmt: str,
    started_at: str,
    ended_at: str,
    tool_version: str,
    targets: List[TargetScanResult],
    open_only: bool,
) -> None:
    if fmt == "auto":
        if path.lower().endswith(".json"):
            fmt = "json"
        elif path.lower().endswith(".csv"):
            fmt = "csv"
        else:
            fmt = "text"

    if fmt == "json":
        scanned_total = sum(item.scanned_total for item in targets)
        open_total = sum(item.open_total for item in targets)
        payload = {
            "tool": {"name": TOOL_NAME, "version": tool_version},
            "started_at": started_at,
            "ended_at": ended_at,
            "targets_scanned": len(targets),
            "scanned_ports_total": scanned_total,
            "open_ports_total": open_total,
            "targets": [],
        }
        for item in targets:
            rows = item.results
            if open_only:
                rows = [row for row in rows if row["open"]]
            payload["targets"].append(
                {
                    "target": {"host": item.target.host, "ip": item.target.ip},
                    "scanned_ports": item.scanned_total,
                    "open_ports": item.open_total,
                    "duration_seconds": round(item.duration_s, 4),
                    "results": rows,
                }
            )
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2)
        return

    if fmt == "csv":
        with open(path, "w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(
                handle,
                fieldnames=["host", "ip", "port", "open", "service", "banner", "scanned_at"],
            )
            writer.writeheader()
            for item in targets:
                rows = item.results
                if open_only:
                    rows = [row for row in rows if row["open"]]
                for row in rows:
                    writer.writerow(
                        {
                            "host": item.target.host,
                            "ip": item.target.ip,
                            "port": row["port"],
                            "open": row["open"],
                            "service": row.get("service", ""),
                            "banner": row.get("banner", ""),
                            "scanned_at": started_at,
                        }
                    )
        return

    with open(path, "w", encoding="utf-8") as handle:
        scanned_total = sum(item.scanned_total for item in targets)
        open_total = sum(item.open_total for item in targets)
        handle.write(f"Tool: {TOOL_NAME} {tool_version}\n")
        handle.write(f"Started: {started_at}\n")
        handle.write(f"Ended: {ended_at}\n")
        handle.write(f"Targets: {len(targets)}\n")
        handle.write(f"Scanned: {scanned_total} | Open: {open_total}\n")
        handle.write("\n")
        for item in targets:
            handle.write(f"Target: {item.target.host} ({item.target.ip})\n")
            handle.write(
                f"Scanned: {item.scanned_total} | Open: {item.open_total} | Duration: {item.duration_s:.3f}s\n"
            )
            handle.write("\n")
            rows = item.results
            if open_only:
                rows = [row for row in rows if row["open"]]
            for row in rows:
                status = "open" if row["open"] else "closed"
                service = row.get("service") or ""
                banner = row.get("banner") or ""
                if service:
                    line = f"{row['port']}/tcp {status} ({service})"
                else:
                    line = f"{row['port']}/tcp {status}"
                if banner:
                    preview = format_banner_preview(banner)
                    line += f" [banner: {preview}]"
                handle.write(f"{line}\n")
            handle.write("\n")


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
    parser.add_argument(
        "--hosts",
        help="Comma-separated list of hosts or IPs",
        default=None,
    )
    parser.add_argument(
        "--host-file",
        help="File with one host or IP per line",
        default=None,
    )
    parser.add_argument(
        "--cidr",
        help="CIDR block to scan, e.g. 192.168.1.0/24 or 2001:db8::/120",
        default=None,
    )
    parser.add_argument(
        "--range",
        help="IP range to scan, e.g. 192.168.1.10-192.168.1.50",
        default=None,
    )
    parser.add_argument(
        "--max-hosts",
        type=int,
        default=None,
        help="Safety limit for number of targets (default: 1024)",
    )
    parser.add_argument(
        "--engine",
        choices=["async", "thread"],
        default=None,
        help="Scanning engine (async or thread)",
    )
    parser.add_argument(
        "--profile",
        choices=sorted(RATE_PROFILES),
        default=None,
        help="Rate-limit profile (stealth, polite, normal, fast)",
    )
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
        "--retries",
        type=int,
        default=None,
        help="Retry failed ports (default: 0)",
    )
    parser.add_argument(
        "--retry-delay",
        type=float,
        default=None,
        help="Delay before first retry (s)",
    )
    parser.add_argument(
        "--retry-backoff",
        type=float,
        default=None,
        help="Backoff multiplier for retries (>= 1.0)",
    )
    parser.add_argument(
        "--retry-on",
        choices=["transient", "timeout", "any"],
        default=None,
        help="Retry on transient errors, only timeouts, or any failure",
    )
    parser.add_argument(
        "--banner",
        action="store_true",
        default=None,
        help="Attempt to read a simple banner from open ports",
    )
    parser.add_argument(
        "--banner-bytes",
        type=int,
        default=None,
        help="Max bytes to read for a banner (default: 512)",
    )
    parser.add_argument(
        "--banner-timeout",
        type=float,
        default=None,
        help="Timeout for banner read (s)",
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
        targets_raw = collect_targets(settings)
    except ConfigError as exc:
        print(f"Config error: {exc}", file=sys.stderr)
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

    started_at = utc_now_iso()
    port_min = min(ports)
    port_max = max(ports)
    print(colorize("Targets:", "36", color_enabled), f"{len(targets_raw)}")
    print(colorize("Engine:", "36", color_enabled), settings.engine)
    print(
        colorize("Ports:", "36", color_enabled),
        f"{port_min}..{port_max} ({len(ports)} total)",
    )
    print(
        colorize("Timeout:", "36", color_enabled),
        f"{settings.timeout}s | Workers: {settings.workers}",
    )
    if settings.profile:
        print(colorize("Profile:", "36", color_enabled), settings.profile)
    if settings.retries > 0:
        print(
            colorize("Retries:", "36", color_enabled),
            f"{settings.retries} | Delay: {settings.retry_delay}s | Backoff: {settings.retry_backoff} | On: {settings.retry_on}",
        )
    if settings.banner:
        print(
            colorize("Banner:", "36", color_enabled),
            f"{settings.banner_bytes} bytes | Timeout: {settings.banner_timeout}s",
        )
    if settings.delay > 0:
        print(colorize("Schedule delay:", "36", color_enabled), f"{settings.delay}s")
    print()

    target_results: List[TargetScanResult] = []
    failed_targets = 0

    for idx, host in enumerate(targets_raw, start=1):
        try:
            target = resolve_target(host)
        except socket.gaierror as exc:
            print(colorize("Failed:", "31", color_enabled), f"{host} ({exc})")
            failed_targets += 1
            continue

        label = f"Target {idx}/{len(targets_raw)}:" if len(targets_raw) > 1 else "Target:"
        print(colorize(label, "36", color_enabled), f"{target.host} ({target.ip})")

        result = scan_ports_for_target(target, ports, settings, show_progress)
        open_rows = [row for row in result.results if row["open"]]

        if not open_rows:
            print(colorize("No open ports found.", "33", color_enabled))
        else:
            print(colorize("Open ports:", "32", color_enabled))
            for row in open_rows:
                service = row.get("service") or ""
                banner = row.get("banner") or ""
                if service:
                    line = f"- {row['port']}/tcp ({service})"
                else:
                    line = f"- {row['port']}/tcp"
                if banner:
                    line += f" [banner: {format_banner_preview(banner)}]"
                print(line)

        print()
        print(colorize("Summary:", "36", color_enabled))
        print(
            f"Scanned: {result.scanned_total} | Open: {result.open_total} | Closed: {result.scanned_total - result.open_total}"
        )
        print(f"Duration: {result.duration_s:.3f}s")
        print()
        target_results.append(result)

    if not target_results:
        print("No targets could be scanned.", file=sys.stderr)
        return 2

    ended_at = utc_now_iso()

    if len(target_results) > 1:
        total_scanned = sum(item.scanned_total for item in target_results)
        total_open = sum(item.open_total for item in target_results)
        print(colorize("Overall:", "36", color_enabled))
        print(
            f"Targets: {len(target_results)} | Scanned: {total_scanned} | Open: {total_open}"
        )
        if failed_targets:
            print(f"Failed targets: {failed_targets}")
        print()

    if settings.output:
        write_output(
            settings.output,
            settings.format,
            started_at,
            ended_at,
            __version__,
            target_results,
            settings.open_only,
        )
        print(colorize("Saved:", "32", color_enabled), settings.output)

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))


def cli_main() -> None:
    raise SystemExit(main(sys.argv[1:]))
