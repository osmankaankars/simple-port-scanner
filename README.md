# Simple Port Scanner (Educational)

This is a small, safe-by-default TCP port scanner for educational use on
systems you own or have explicit permission to test.

## Features
- Single host scanning (hostname or IP)
- Custom port lists and ranges (e.g. `22,80,443,8000-8100`)
- Timeouts and worker limits
- Optional lightweight service guess

## Usage
```bash
python3 port_scanner.py --host 127.0.0.1 --ports 22,80,443
```

Scan a small range:
```bash
python3 port_scanner.py --host localhost --ports 8000-8100
```

Limit concurrency:
```bash
python3 port_scanner.py --host 127.0.0.1 --ports 1-1024 --workers 50
```

Scan common ports:
```bash
python3 port_scanner.py --host 127.0.0.1 --common
```

Scan top 20 ports:
```bash
python3 port_scanner.py --host 127.0.0.1 --top20
```

Sequential scan:
```bash
python3 port_scanner.py --host 127.0.0.1 --ports 1-1024 --sequential
```

Save results (JSON/CSV):
```bash
python3 port_scanner.py --host 127.0.0.1 --ports 1-1024 --output results.json
python3 port_scanner.py --host 127.0.0.1 --ports 1-1024 --output results.csv
```

Only open ports in output file:
```bash
python3 port_scanner.py --host 127.0.0.1 --ports 1-1024 --open-only --output results.json
```

Disable colors:
```bash
python3 port_scanner.py --host 127.0.0.1 --ports 1-1024 --no-color
```

Disable progress indicator:
```bash
python3 port_scanner.py --host 127.0.0.1 --ports 1-1024 --no-progress
```

## Notes
- Only scan targets you own or have permission to test.
- This tool performs a basic TCP connect scan; it does not attempt to
  evade detection or bypass security controls.
