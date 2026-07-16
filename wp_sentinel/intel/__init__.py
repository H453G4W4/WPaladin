"""Vulnerability-intelligence layer: correlate versions against known advisories."""

from .advisories import Advisory, VulnerabilityDatabase, parse_version

__all__ = ["Advisory", "VulnerabilityDatabase", "parse_version"]
