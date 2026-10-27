import io
import json
import pytest
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import app as flask_app_module
from app import app, HISTORY, REPORT_DIR
from modules.analyzer import estimate_entropy, analyze_password
from modules.brute_force import search_space_size, bounded_bruteforce
from modules.hash_formats import identify_hash, parse_lab_hash_file
from modules.hash_simulator import sha256_hash, dictionary_hash_test
from modules.report import save_report_json, save_report_csv


@pytest.fixture
def client():
    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = False
    with app.test_client() as client:
        with client.session_transaction() as sess:
            sess["_csrf_token"] = "test-csrf-token"
        yield client


@pytest.fixture(autouse=True)
def clean_history():
    HISTORY.clear()
    yield
    HISTORY.clear()


def test_csrf_protection_blocks_invalid_post(client):
    """Ensure POST requests without valid CSRF tokens are rejected with a warning."""
    # Temporarily remove session token or send wrong token
    res = client.post("/analyzer", data={"password": "TestPassword123!"})
    # Redirects back with flash message
    assert res.status_code == 302
    assert len(HISTORY) == 0


def test_analyzer_route_and_history(client):
    """Test analyzing a password records history without logging plaintext."""
    res = client.post(
        "/analyzer",
        data={"password": "password123", "csrf_token": "test-csrf-token"},
        follow_redirects=True,
    )
    assert res.status_code == 200
    assert len(HISTORY) == 1
    record = HISTORY[0]
    assert record["test_type"] == "Password Analysis"
    assert record["strength"] == "Weak"
    assert record["common_word_match"] is True
    assert record["dictionary_match"] is False
    assert record["bruteforce_match"] is False
    assert "password123" not in json.dumps(record)


def test_analyzer_empty_input(client):
    """Analyzer handles empty password submission gracefully without server error."""
    res = client.post(
        "/analyzer",
        data={"password": "", "csrf_token": "test-csrf-token"},
        follow_redirects=True,
    )
    assert res.status_code == 200
    assert len(HISTORY) == 0
    assert b"Enter a password to analyze." in res.data


def test_dictionary_generation_and_download(client):
    """Test wordlist generation and download route."""
    res = client.post(
        "/dictionary",
        data={"name": "testcorp", "year": "2026", "keyword": "admin", "csrf_token": "test-csrf-token"},
        follow_redirects=True,
    )
    assert res.status_code == 200
    assert b"Generated" in res.data

    dl_res = client.get("/download-wordlist")
    assert dl_res.status_code == 200
    assert b"testcorp" in dl_res.data


def test_hash_simulator_route_match_and_history(client):
    """Test hash simulator detects matches and tracks history cleanly."""
    target = sha256_hash("secret123")
    res = client.post(
        "/hash-simulator",
        data={
            "target_hash": target,
            "candidates": "wrong1\nsecret123\nwrong2",
            "csrf_token": "test-csrf-token",
        },
        follow_redirects=True,
    )
    assert res.status_code == 200
    assert b"Match identified!" in res.data
    assert len(HISTORY) == 1
    record = HISTORY[0]
    assert record["test_type"] == "Hash Simulation"
    assert record["dictionary_match"] is True
    assert record["common_word_match"] is False
    # Verify candidate password is not recorded in the history log
    assert "secret123" not in json.dumps(record)


def test_hash_simulator_invalid_inputs(client):
    """Test hash simulator with malformed hash and empty candidate list."""
    # Short/malformed hash
    res = client.post(
        "/hash-simulator",
        data={"target_hash": "1234abcd", "candidates": "test", "csrf_token": "test-csrf-token"},
        follow_redirects=True,
    )
    assert res.status_code == 200
    assert b"Enter a valid SHA-256 hexadecimal hash" in res.data
    assert len(HISTORY) == 0

    # Valid hash format, but empty candidates
    target = sha256_hash("abc")
    res2 = client.post(
        "/hash-simulator",
        data={"target_hash": target, "candidates": "   \n\n", "csrf_token": "test-csrf-token"},
        follow_redirects=True,
    )
    assert res2.status_code == 200
    assert b"Enter at least one test candidate." in res2.data
    assert len(HISTORY) == 0


def test_brute_force_simulation_and_history(client):
    """Test brute-force simulation route and history recording."""
    res = client.post(
        "/brute-force",
        data={
            "target": "ab",
            "max_length": "2",
            "charset": "lowercase",
            "csrf_token": "test-csrf-token",
        },
        follow_redirects=True,
    )
    assert res.status_code == 200
    assert b"Target discovered within search space!" in res.data
    assert len(HISTORY) == 1
    record = HISTORY[0]
    assert record["test_type"] == "Brute-Force Sim"
    assert record["bruteforce_match"] is True
    assert record["dictionary_match"] is False
    # Plaintext target should not be logged
    assert record.get("candidate") is None


def test_brute_force_validation_errors(client):
    """Test brute-force invalid length, charset, and empty target."""
    # Invalid length (exceeds 4)
    res = client.post(
        "/brute-force",
        data={"target": "abcde", "max_length": "5", "charset": "lowercase", "csrf_token": "test-csrf-token"},
        follow_redirects=True,
    )
    assert res.status_code == 200
    assert b"Maximum length is limited" in res.data

    # Invalid length (non-numeric)
    res = client.post(
        "/brute-force",
        data={"target": "abc", "max_length": "invalid", "charset": "lowercase", "csrf_token": "test-csrf-token"},
        follow_redirects=True,
    )
    assert res.status_code == 200
    assert b"Maximum length is limited" in res.data

    # Invalid charset
    res = client.post(
        "/brute-force",
        data={"target": "abc", "max_length": "3", "charset": "malicious_eval", "csrf_token": "test-csrf-token"},
        follow_redirects=True,
    )
    assert res.status_code == 200
    assert b"Unsupported character set" in res.data

    # Empty target
    res = client.post(
        "/brute-force",
        data={"target": "", "max_length": "3", "charset": "lowercase", "csrf_token": "test-csrf-token"},
        follow_redirects=True,
    )
    assert res.status_code == 200
    assert b"Enter a lab-only target password." in res.data


def test_hash_inspector_upload_and_tracking(client):
    """Test file upload, format inspection, extension validation, and history tracking."""
    # Disallowed extension
    data = {
        "lab_file": (io.BytesIO(b"root:$6$rounds=5000$salt$abc"), "malicious.exe"),
        "csrf_token": "test-csrf-token",
    }
    res = client.post("/hash-inspector", data=data, content_type="multipart/form-data", follow_redirects=True)
    assert res.status_code == 200
    assert b"Invalid file format" in res.data
    assert len(HISTORY) == 0

    # Valid upload
    valid_data = {
        "lab_file": (io.BytesIO(b"root:$6$rounds=5000$salt$abc\nalice:5f4dcc3b5aa765d61d8327deb882cf99"), "hashes.txt"),
        "csrf_token": "test-csrf-token",
    }
    res_valid = client.post("/hash-inspector", data=valid_data, content_type="multipart/form-data", follow_redirects=True)
    assert res_valid.status_code == 200
    assert b"Analyzed 2 lab records" in res_valid.data
    assert len(HISTORY) == 1
    assert HISTORY[0]["test_type"] == "Hash Inspection"
    assert HISTORY[0]["attempts"] == 2


def test_dashboard_statistics_and_clear_history(client):
    """Test dashboard metrics calculation and clear history route."""
    # Populate mixed events
    HISTORY.append({
        "test_type": "Password Analysis",
        "strength": "Weak",
        "severity": "High",
        "common_word_match": True,
        "dictionary_match": False,
        "bruteforce_match": False,
    })
    HISTORY.append({
        "test_type": "Hash Simulation",
        "strength": "Weak",
        "severity": "High",
        "common_word_match": False,
        "dictionary_match": True,
        "bruteforce_match": False,
    })
    HISTORY.append({
        "test_type": "Brute-Force Sim",
        "strength": "Weak",
        "severity": "High",
        "common_word_match": False,
        "dictionary_match": False,
        "bruteforce_match": True,
    })

    res = client.get("/")
    assert res.status_code == 200
    assert b"Total Tests" in res.data

    # Clear history
    clear_res = client.post(
        "/clear-history",
        data={"csrf_token": "test-csrf-token"},
        follow_redirects=True,
    )
    assert clear_res.status_code == 200
    assert len(HISTORY) == 0
    assert b"Dashboard test history cleared." in clear_res.data


def test_reports_generate_json_and_csv(client, tmp_path):
    """Test report generation, ensuring JSON and CSV exports reflect recorded events without plaintext."""
    HISTORY.append({
        "timestamp": "2026-10-25 12:00:00",
        "test_type": "Password Analysis",
        "strength": "Weak",
        "severity": "High",
        "entropy": 18.0,
        "length": 8,
        "common_word_match": True,
        "dictionary_match": False,
        "bruteforce_match": False,
        "attempts": "",
        "rate": "",
        "search_space": "",
        "estimated_worst_case": "",
        "details": "Score: 20/100",
    })

    res = client.post(
        "/reports/generate",
        data={"csrf_token": "test-csrf-token"},
        follow_redirects=True,
    )
    assert res.status_code == 200
    assert b"JSON and CSV reports generated." in res.data

    json_report = REPORT_DIR / "security_audit_report.json"
    csv_report = REPORT_DIR / "security_audit_results.csv"

    assert json_report.exists()
    assert csv_report.exists()

    json_data = json.loads(json_report.read_text(encoding="utf-8"))
    assert json_data["metadata"]["auditor"] == "Aniket"
    assert json_data["summary"]["total_tests"] == 1
    assert json_data["summary"]["common_word_matches"] == 1
    assert json_data["summary"]["dictionary_matches"] == 0

    csv_data = csv_report.read_text(encoding="utf-8")
    assert "common_word_match" in csv_data
    assert "dictionary_match" in csv_data
    assert "Password Analysis" in csv_data


def test_entropy_and_boundary_conditions():
    """Verify entropy estimation and edge cases."""
    assert estimate_entropy("") == 0.0
    assert estimate_entropy("a") > 0.0
    assert estimate_entropy("123456") > 0.0
    # Special characters
    assert estimate_entropy("!@#$") > 0.0
    # Brute force search space edge cases
    with pytest.raises(ValueError):
        search_space_size(0, "lowercase")
    with pytest.raises(ValueError):
        search_space_size(2, "non_existent_charset")
    with pytest.raises(ValueError):
        bounded_bruteforce("", 2, "lowercase")
    with pytest.raises(ValueError):
        bounded_bruteforce("test", 5, "lowercase")
