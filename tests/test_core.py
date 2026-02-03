import argparse
from pathlib import Path

import pytest

import port_scanner as ps


def make_settings(**overrides: object) -> ps.Settings:
    base = {
        "host": None,
        "hosts": None,
        "host_file": None,
        "cidr": None,
        "host_range": None,
        "max_hosts": ps.DEFAULTS["max_hosts"],
        "engine": ps.DEFAULTS["engine"],
        "profile": None,
        "ports": "22",
        "common": False,
        "top20": False,
        "timeout": ps.DEFAULTS["timeout"],
        "workers": ps.DEFAULTS["workers"],
        "sequential": False,
        "delay": ps.DEFAULTS["delay"],
        "retries": ps.DEFAULTS["retries"],
        "retry_delay": ps.DEFAULTS["retry_delay"],
        "retry_backoff": ps.DEFAULTS["retry_backoff"],
        "retry_on": ps.DEFAULTS["retry_on"],
        "banner": False,
        "banner_bytes": ps.DEFAULTS["banner_bytes"],
        "banner_timeout": ps.DEFAULTS["banner_timeout"],
        "service": False,
        "open_only": False,
        "output": None,
        "format": "auto",
        "no_color": False,
        "no_progress": False,
    }
    base.update(overrides)
    return ps.Settings(**base)


def test_parse_ports_dedup_and_range() -> None:
    ports = ps.parse_ports("80,443,80,20-22")
    assert ports == [80, 443, 20, 21, 22]


def test_parse_ports_filters_invalid() -> None:
    ports = ps.parse_ports("0,70000,22")
    assert ports == [22]


def test_expand_ip_range_reversed() -> None:
    hosts = ps.expand_ip_range("192.168.1.5-192.168.1.3", remaining=10)
    assert hosts == ["192.168.1.3", "192.168.1.4", "192.168.1.5"]


def test_expand_ip_range_limit() -> None:
    with pytest.raises(ps.ConfigError):
        ps.expand_ip_range("192.168.1.1-192.168.1.5", remaining=2)


def test_expand_cidr_limit() -> None:
    with pytest.raises(ps.ConfigError):
        ps.expand_cidr("192.168.1.0/30", remaining=1)


def test_collect_targets_dedup_and_file(tmp_path: Path) -> None:
    host_file = tmp_path / "targets.txt"
    host_file.write_text("127.0.0.1\n# comment\nlocalhost\n127.0.0.1\n")
    settings = make_settings(
        host="127.0.0.1",
        hosts="127.0.0.1,localhost",
        host_file=str(host_file),
    )
    targets = ps.collect_targets(settings)
    assert targets == ["127.0.0.1", "localhost"]


def test_collect_targets_limit() -> None:
    settings = make_settings(hosts="1.1.1.1,2.2.2.2,3.3.3.3", max_hosts=2)
    with pytest.raises(ps.ConfigError):
        ps.collect_targets(settings)


def test_decode_banner_bytes() -> None:
    text = ps.decode_banner_bytes(b"hello\r\nworld\n")
    assert text == "hello\\r\\nworld\\n"


def test_merge_settings_requires_ports_or_preset() -> None:
    args = argparse.Namespace(
        host="127.0.0.1",
        hosts=None,
        host_file=None,
        cidr=None,
        range=None,
        max_hosts=None,
        engine=None,
        profile=None,
        ports=None,
        common=None,
        top20=None,
        timeout=None,
        workers=None,
        sequential=None,
        delay=None,
        retries=None,
        retry_delay=None,
        retry_backoff=None,
        retry_on=None,
        banner=None,
        banner_bytes=None,
        banner_timeout=None,
        service=None,
        open_only=None,
        output=None,
        format=None,
        no_color=None,
        no_progress=None,
    )
    with pytest.raises(ps.ConfigError):
        ps.merge_settings(args, {})
