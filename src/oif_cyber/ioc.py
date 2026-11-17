"""Normalize defensive indicators while retaining provenance."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
from pathlib import Path
from urllib.parse import urlsplit


def normalize_indicator(kind: str, value: str) -> str:
    raw = value.strip()
    if not raw:
        raise ValueError("indicator value is empty")
    if kind == "ipv4":
        address = ipaddress.ip_address(raw)
        if address.version != 4:
            raise ValueError("expected IPv4 address")
        return str(address)
    if kind == "domain":
        domain = raw.rstrip(".").lower()
        if len(domain) > 253 or not domain or any(not label or len(label) > 63 for label in domain.split(".")):
            raise ValueError("invalid domain")
        if any(not all(ch.isalnum() or ch == "-" for ch in label) or label.startswith("-") or label.endswith("-") for label in domain.split(".")):
            raise ValueError("invalid domain")
        return domain
    if kind == "url":
        parsed = urlsplit(raw)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("URL must use http or https and include a host")
        return raw
    if kind == "sha256":
        digest = raw.lower()
        if len(digest) != 64 or any(ch not in "0123456789abcdef" for ch in digest):
            raise ValueError("SHA-256 must contain exactly 64 hexadecimal characters")
        return digest
    raise ValueError(f"unsupported indicator type: {kind}")


def normalize_record(record: dict) -> dict:
    normalized = dict(record)
    normalized["value"] = normalize_indicator(record["type"], record["value"])
    normalized.setdefault("source", "unspecified")
    normalized.setdefault("observed_at", "unknown")
    normalized["record_fingerprint"] = hashlib.sha256(
        f"{normalized['type']}|{normalized['value']}|{normalized['source']}|{normalized['observed_at']}".encode()
    ).hexdigest()
    return normalized


def main() -> int:
    parser = argparse.ArgumentParser(description="Normalize defensive IOC records.")
    parser.add_argument("input", type=Path)
    args = parser.parse_args()
    records = json.loads(args.input.read_text(encoding="utf-8"))
    output = []
    for record in records:
        output.append(normalize_record(record))
    print(json.dumps(output, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
