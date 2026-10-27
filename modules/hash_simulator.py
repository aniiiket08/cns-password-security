import hashlib

def sha256_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def dictionary_hash_test(target_hash: str, candidates: list[str]) -> dict:
    attempts = 0
    for candidate in candidates:
        attempts += 1
        if sha256_hash(candidate) == target_hash:
            return {
                "found": True,
                "candidate": candidate,
                "attempts": attempts,
            }

    return {
        "found": False,
        "candidate": None,
        "attempts": attempts,
    }
