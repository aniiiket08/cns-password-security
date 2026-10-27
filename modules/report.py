import csv
import json
from pathlib import Path


def save_report_json(payload, path: Path):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = path.with_suffix(path.suffix + ".tmp")
    try:
        temp_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        temp_path.replace(path)
    except Exception:
        if temp_path.exists():
            temp_path.unlink()
        raise


def save_report_csv(rows, path: Path):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = [
        "timestamp", "test_type", "strength", "severity", "entropy", "length",
        "common_word_match", "dictionary_match", "bruteforce_match", "attempts", "rate",
        "search_space", "estimated_worst_case", "details",
    ]
    temp_path = path.with_suffix(path.suffix + ".tmp")
    try:
        with temp_path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fields)
            writer.writeheader()
            for row in rows:
                writer.writerow({field: row.get(field, "") for field in fields})
        temp_path.replace(path)
    except Exception:
        if temp_path.exists():
            temp_path.unlink()
        raise

