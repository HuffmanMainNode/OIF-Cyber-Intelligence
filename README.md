# OIF Cyber Intelligence

**Defensive indicator normalization and evidence-aware threat-intelligence handling.**

This repository provides a local utility for normalizing common indicators of compromise (IOCs) and preserving their source context. It is a defensive data-preparation component, not a scanner, exploit framework, attribution engine, or live threat feed.

## Implemented

- Normalization for IPv4 addresses, domains, URLs, and SHA-256 hashes.
- Basic syntax checks using Python's standard library.
- Source and observation metadata retained alongside normalized values.
- Deterministic deduplication that preserves distinct source records.
- Tests for valid and invalid indicators.

## Quick start

```bash
python -m pip install -e .
python -m unittest discover -s tests -v
oif-ioc-normalize examples/iocs.json
```

## Evidence and handling

An IOC is a lead, not proof of compromise. Preserve the source, first-seen time, collection method, confidence rationale, and expiry/review date. Do not infer actor identity from an indicator alone. Avoid publishing victim-identifying or sensitive incident details.

The data model is intentionally compatible with future STIX/TAXII or MISP adapters, but this initial package does not claim full conformance with either standard.

## Scope

This repository owns defensive indicator normalization and source preservation. General research evidence records belong in [OIF-Research-Observatory](https://github.com/HuffmanMainNode/OIF-Research-Observatory); AI-specific threats and model safeguards belong in [OIF-AI-Security](https://github.com/HuffmanMainNode/OIF-AI-Security).
