# Simple Port Scanner (Educational)

[![License](https://img.shields.io/github/license/osmankaankars/simple-port-scanner)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.8%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![CI](https://github.com/osmankaankars/simple-port-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/osmankaankars/simple-port-scanner/actions/workflows/ci.yml)

Safe-by-default TCP port scanner for learning and testing on systems you own
or have explicit permission to assess.

## Features
- IPv4 + IPv6 targets
- Multiple target sources: single host, list, file, CIDR, or range
- Custom port lists and ranges (e.g. `22,80,443,8000-8100`)
- Presets for common ports and top 20 ports
- Timeouts, concurrency limits, and optional scheduling delays
- Retry/backoff for transient failures
- Rate-limit profiles (stealth, polite, normal, fast)
- Optional banner grabbing (read-only, off by default)
- Optional lightweight service guess for open ports
- Output to text, JSON, or CSV (with open-only option)
- Safety limit for large target sets (`--max-hosts`)
- Async scanning engine with thread fallback (`--engine`)

## Requirements
- Python 3.8+

## Quick Start
```bash
python3 port_scanner.py --host 127.0.0.1 --top20
```

## Screenshot
![Terminal demo](assets/terminal-demo.svg)

## Usage
```bash
python3 port_scanner.py --help
```

## Config File
You can provide settings via JSON (or YAML if `pyyaml` is installed).

`config.json`:
```json
{
  "hosts": "127.0.0.1,::1",
  "top20": true,
  "engine": "async",
  "profile": "polite",
  "service": true,
  "output": "results.json",
  "max_hosts": 1024
}
```

Run with:
```bash
python3 port_scanner.py --config config.json
```
See `config.example.json` for a ready-to-copy sample.

YAML example (requires `pip install pyyaml`):
```yaml
host: 127.0.0.1
ports: "22,80,443,8000-8100"
timeout: 0.5
workers: 50
output: results.csv
```

Config supports these target keys:
- `host` (single target)
- `hosts` (comma-separated list or YAML list)
- `host_file` (one target per line)
- `cidr` (IPv4/IPv6 block)
- `range` (IP range like `192.168.1.10-192.168.1.50`)
- `max_hosts` (safety limit)
- `profile` (rate-limit profile)
- `retries`, `retry_delay`, `retry_backoff`, `retry_on`
- `banner`, `banner_bytes`, `banner_timeout`
- `engine` (`async` or `thread`)

## Examples
```bash
python3 port_scanner.py --host 127.0.0.1 --ports 22,80,443
python3 port_scanner.py --host localhost --ports 8000-8100
python3 port_scanner.py --host 127.0.0.1 --ports 1-1024 --workers 50
python3 port_scanner.py --host 127.0.0.1 --common
python3 port_scanner.py --host 127.0.0.1 --top20
python3 port_scanner.py --host 127.0.0.1 --ports 1-1024 --sequential
python3 port_scanner.py --host 127.0.0.1 --ports 1-1024 --delay 0.01
python3 port_scanner.py --host 127.0.0.1 --ports 1-1024 --service
python3 port_scanner.py --hosts 127.0.0.1,::1 --top20
python3 port_scanner.py --host-file targets.txt --common
python3 port_scanner.py --cidr 192.168.1.0/24 --ports 22,80,443 --max-hosts 512
python3 port_scanner.py --range 192.168.1.10-192.168.1.50 --top20
python3 port_scanner.py --host 127.0.0.1 --top20 --profile polite
python3 port_scanner.py --host 127.0.0.1 --ports 1-1024 --retries 2 --retry-delay 0.1 --retry-backoff 2
python3 port_scanner.py --host 127.0.0.1 --ports 1-1024 --retry-on timeout --retries 1
python3 port_scanner.py --host 127.0.0.1 --top20 --banner
python3 port_scanner.py --host 127.0.0.1 --ports 1-1024 --banner --banner-bytes 256 --banner-timeout 0.2
python3 port_scanner.py --host 127.0.0.1 --top20 --engine thread
python3 port_scanner.py --host 127.0.0.1 --ports 1-1024 --output results.json
python3 port_scanner.py --host 127.0.0.1 --ports 1-1024 --output results.csv
python3 port_scanner.py --host 127.0.0.1 --ports 1-1024 --open-only --output results.json
python3 port_scanner.py --host 127.0.0.1 --ports 1-1024 --no-color
python3 port_scanner.py --host 127.0.0.1 --ports 1-1024 --no-progress
```

## Example Output
```text
Targets: 1
Engine: async
Ports: 20..5900 (20 total)
Timeout: 0.5s | Workers: 100

Target: 127.0.0.1 (127.0.0.1)

Open ports:
- 22/tcp (ssh)
- 80/tcp (http)

Summary:
Scanned: 20 | Open: 2 | Closed: 18
Duration: 0.042s
```

## Output
- Text output lists `port/tcp` and status.
- JSON includes `tool`, `started_at`, `ended_at`, `targets_scanned`, totals, and per-target results.
- CSV columns are `host`, `ip`, `port`, `open`, `service`, `banner`, and `scanned_at`.

## Development
```bash
python3 -m pip install -r requirements-dev.txt
ruff check .
ruff format --check .
python3 -m pytest
```

## Safety Notes
- Only scan targets you own or have permission to test.
- This tool performs a basic TCP connect scan and does not attempt to evade detection.

## License
MIT. See `LICENSE`.
