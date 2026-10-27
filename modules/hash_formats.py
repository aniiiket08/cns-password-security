import re
from pathlib import Path

HASH_PATTERNS = [
    ("Linux shadow / yescrypt", re.compile(r"^\$y\$")),
    ("Linux shadow / SHA-512", re.compile(r"^\$6\$")),
    ("Linux shadow / SHA-256", re.compile(r"^\$5\$")),
    ("Linux shadow / bcrypt", re.compile(r"^\$2[aby]\$")),
    ("Linux shadow / MD5", re.compile(r"^\$1\$")),
    ("NTLM (32 hex characters)", re.compile(r"^[0-9a-fA-F]{32}$")),
    ("MD5 (32 hex characters)", re.compile(r"^[0-9a-fA-F]{32}$")),
    ("SHA-1 (40 hex characters)", re.compile(r"^[0-9a-fA-F]{40}$")),
    ("SHA-256 (64 hex characters)", re.compile(r"^[0-9a-fA-F]{64}$")),
    ("SHA-512 (128 hex characters)", re.compile(r"^[0-9a-fA-F]{128}$")),
]


def identify_hash(value: str) -> dict:
    value = value.strip()
    if not value:
        return {"format": "Unknown", "confidence": "None", "hash": ""}

    # Linux shadow records contain username and fields separated by ':'.
    if ":" in value:
        parts = value.split(":")
        if len(parts) >= 2 and parts[1].startswith("$"):
            value = parts[1]
            for name, pattern in HASH_PATTERNS[:5]:
                if pattern.search(value):
                    return {"format": name, "confidence": "High", "hash": value}
            return {"format": "Linux shadow-style entry", "confidence": "Medium", "hash": value}

    # A bare 32-character digest is ambiguous: it can be MD5 or NTLM.
    if re.fullmatch(r"[0-9a-fA-F]{32}", value):
        return {
            "format": "MD5 or NTLM (ambiguous 32-hex digest)",
            "confidence": "Low",
            "hash": value,
            "note": "Hash length alone cannot distinguish MD5 from NTLM.",
        }

    for name, pattern in HASH_PATTERNS:
        if value.startswith("$") and pattern.search(value):
            return {"format": name, "confidence": "High", "hash": value}
        if pattern.fullmatch(value):
            return {"format": name, "confidence": "High", "hash": value}

    if value.startswith("$"):
        return {"format": "Linux shadow-style hash", "confidence": "Medium", "hash": value}

    return {"format": "Unknown", "confidence": "None", "hash": value}


def parse_lab_hash_file(text: str) -> list[dict]:
    """Parse user-supplied lab text only; never reads OS credential stores."""
    records = []
    for line_no, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        username = ""
        candidate = line
        if ":" in line:
            first, rest = line.split(":", 1)
            if first and rest:
                username = first
                candidate = line
        result = identify_hash(candidate)
        if result["format"] == "Unknown" and username:
            result = identify_hash(line.split(":", 1)[1])
        records.append({"line": line_no, "username": username, **result})
    return records


def parse_lab_hash_file_path(path: Path) -> list[dict]:
    return parse_lab_hash_file(path.read_text(encoding="utf-8", errors="replace"))
