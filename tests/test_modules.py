import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from modules.analyzer import analyze_password
from modules.brute_force import bounded_bruteforce, search_space_size
from modules.dictionary_generator import generate_dictionary
from modules.hash_formats import identify_hash, parse_lab_hash_file
from modules.hash_simulator import sha256_hash, dictionary_hash_test


def test_analyzer():
    result = analyze_password("password123")
    assert result["strength"] == "Weak"
    assert result["severity"] == "High"
    assert result["dictionary_match"] is True


def test_dictionary_generator():
    words = generate_dictionary("demo", "2026", "lab")
    assert "demo" in words
    assert "demo2026" in words
    assert any("@" in word or "3" in word for word in words)


def test_hash_simulator():
    target = sha256_hash("abc")
    result = dictionary_hash_test(target, ["nope", "abc"])
    assert result["found"] is True
    assert result["candidate"] == "abc"


def test_bruteforce_and_search_space():
    assert search_space_size(2, "lowercase") == 26 + 26**2
    result = bounded_bruteforce("ab", 2, "lowercase")
    assert result["found"] is True
    assert result["candidate"] == "ab"
    assert result["search_space"] == 702


def test_hash_formats():
    assert identify_hash("$6$rounds=5000$salt$abc")["format"] == "Linux shadow / SHA-512"
    assert "ambiguous" in identify_hash("5f4dcc3b5aa765d61d8327deb882cf99")["format"]
    assert identify_hash("da39a3ee5e6b4b0d3255bfef95601890afd80709")["format"] == "SHA-1 (40 hex characters)"


def test_lab_parser():
    rows = parse_lab_hash_file("alice:$6$rounds=5000$salt$abc\n# comment\nsha:da39a3ee5e6b4b0d3255bfef95601890afd80709")
    assert len(rows) == 2
    assert rows[0]["username"] == "alice"
    assert rows[1]["format"] == "SHA-1 (40 hex characters)"
