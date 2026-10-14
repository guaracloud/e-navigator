"""Parse bounded workload cell IDs without assigning a deployment namespace."""
import re


def cell_family(value):
    match = re.fullmatch(r"[A-Z][A-Z0-9_]{0,15}-([A-Z]{1,16})-[0-9]{4}", value) if isinstance(value, str) else None
    if match is None:
        raise ValueError("invalid workload cell ID")
    return match.group(1)
