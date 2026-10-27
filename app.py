from flask import Flask, render_template, request, redirect, url_for, flash, send_file, session
from pathlib import Path
from modules.analyzer import analyze_password
from modules.dictionary_generator import generate_dictionary, save_wordlist
from modules.hash_simulator import sha256_hash, dictionary_hash_test
from modules.hash_formats import parse_lab_hash_file
from modules.brute_force import bounded_bruteforce, CHARSETS
from modules.report import save_report_json, save_report_csv
import json
import os
import secrets
import hmac
import hashlib
import datetime

BASE_DIR = Path(__file__).resolve().parent
REPORT_DIR = BASE_DIR / "reports"
DATA_DIR = BASE_DIR / "data"
REPORT_DIR.mkdir(exist_ok=True)
DATA_DIR.mkdir(exist_ok=True)

# Generate a strong persistent fallback secret key in data/ if none provided in environment
SECRET_KEY_FILE = DATA_DIR / ".flask_secret_key"
env_secret = os.environ.get("FLASK_SECRET_KEY")
if env_secret:
    flask_secret = env_secret
else:
    if not SECRET_KEY_FILE.exists():
        SECRET_KEY_FILE.write_text(secrets.token_hex(32), encoding="utf-8")
    flask_secret = SECRET_KEY_FILE.read_text(encoding="utf-8").strip()

app = Flask(__name__)
app.secret_key = flask_secret

# Upload security: Limit uploaded files to 2 MB
MAX_UPLOAD_SIZE = 2 * 1024 * 1024
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_SIZE

ALLOWED_EXTENSIONS = {".txt", ".log", ".lst", ".csv"}

HISTORY = []


def generate_csrf_token():
    if "_csrf_token" not in session:
        session["_csrf_token"] = secrets.token_hex(32)
    return session["_csrf_token"]


@app.context_processor
def inject_csrf_token():
    return dict(csrf_token=generate_csrf_token)


@app.before_request
def csrf_protect():
    if request.method == "POST":
        token = request.form.get("csrf_token")
        expected = session.get("_csrf_token")
        if not expected or not token or not hmac.compare_digest(expected, token):
            flash("Invalid or missing CSRF session token. Please submit the form again.", "danger")
            return redirect(request.referrer or url_for("dashboard"))


@app.errorhandler(413)
def request_entity_too_large(e):
    flash("The uploaded file exceeds the 2 MB security size limit.", "danger")
    return redirect(request.referrer or url_for("hash_inspector"))


@app.route("/")
def dashboard():
    total = len(HISTORY)
    weak = sum(1 for x in HISTORY if x.get("strength") == "Weak")
    medium = sum(1 for x in HISTORY if x.get("strength") == "Medium")
    strong = sum(1 for x in HISTORY if x.get("strength") == "Strong")
    dictionary_hits = sum(1 for x in HISTORY if x.get("dictionary_match"))
    brute_hits = sum(1 for x in HISTORY if x.get("bruteforce_match"))
    common_word_hits = sum(1 for x in HISTORY if x.get("common_word_match"))
    high_risk = sum(1 for x in HISTORY if x.get("severity") == "High")

    chart_data = {
        "labels": ["Weak", "Medium", "Strong"],
        "values": [weak, medium, strong],
        "attack_labels": ["Dictionary matches", "Brute-force matches", "Common-word hits"],
        "attack_values": [dictionary_hits, brute_hits, common_word_hits],
    }
    return render_template(
        "dashboard.html",
        total=total,
        weak=weak,
        medium=medium,
        strong=strong,
        dictionary_hits=dictionary_hits,
        brute_hits=brute_hits,
        high_risk=high_risk,
        chart_data=json.dumps(chart_data),
        history=HISTORY[-10:][::-1],
    )


@app.route("/analyzer", methods=["GET", "POST"])
def analyzer():
    result = None
    if request.method == "POST":
        password = request.form.get("password", "")
        if not password:
            flash("Enter a password to analyze.", "danger")
        else:
            result = analyze_password(password)
            ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            HISTORY.append({
                "test_type": "Password Analysis",
                "timestamp": ts,
                "strength": result["strength"],
                "entropy": result["entropy"],
                "length": result["length"],
                "common_word_match": result["dictionary_match"],
                "dictionary_match": False,
                "bruteforce_match": False,
                "severity": result["severity"],
                "attempts": "",
                "rate": "",
                "search_space": "",
                "estimated_worst_case": "",
                "details": f"Score: {result['score']}/100, Entropy: {result['entropy']} bits",
            })
    return render_template("analyzer.html", result=result)


@app.route("/dictionary", methods=["GET", "POST"])
def dictionary():
    generated = None
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        year = request.form.get("year", "").strip()
        keyword = request.form.get("keyword", "").strip()

        generated = generate_dictionary(name=name, year=year, keyword=keyword)
        path = DATA_DIR / "generated_wordlist.txt"
        save_wordlist(generated, path)
        flash(f"Generated {len(generated)} unique test candidates.", "success")
    return render_template("dictionary.html", generated=generated)


@app.route("/download-wordlist")
def download_wordlist():
    path = DATA_DIR / "generated_wordlist.txt"
    if not path.exists():
        flash("Generate a wordlist first.", "warning")
        return redirect(url_for("dictionary"))
    return send_file(path, as_attachment=True, download_name="generated_wordlist.txt")


@app.route("/hash-simulator", methods=["GET", "POST"])
def hash_simulator():
    result = None
    sample_hash = sha256_hash("Password123!")
    if request.method == "POST":
        target_hash = request.form.get("target_hash", "").strip().lower()
        candidates_input = request.form.get("candidates", "")
        words = [w.strip() for w in candidates_input.splitlines() if w.strip()]

        if not target_hash:
            flash("Target hash cannot be empty.", "danger")
        elif len(target_hash) != 64 or any(c not in "0123456789abcdef" for c in target_hash):
            flash("Enter a valid SHA-256 hexadecimal hash (exactly 64 hex characters).", "danger")
        elif not words:
            flash("Enter at least one test candidate.", "danger")
        else:
            result = dictionary_hash_test(target_hash, words)
            ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            HISTORY.append({
                "test_type": "Hash Simulation",
                "timestamp": ts,
                "strength": "Weak" if result["found"] else "Strong",
                "entropy": "",
                "length": "",
                "common_word_match": False,
                "dictionary_match": result["found"],
                "bruteforce_match": False,
                "severity": "High" if result["found"] else "Low",
                "attempts": result["attempts"],
                "rate": "",
                "search_space": len(words),
                "estimated_worst_case": "",
                "details": f"Target: {target_hash[:8]}... ({'Matched' if result['found'] else 'No collision'})",
            })
    return render_template(
        "hash_simulator.html",
        result=result,
        sample_hash=sample_hash
    )


@app.route("/brute-force", methods=["GET", "POST"])
def brute_force():
    result = None
    if request.method == "POST":
        target = request.form.get("target", "")
        raw_max_length = request.form.get("max_length", "3").strip()
        charset = request.form.get("charset", "lowercase").strip()

        try:
            max_length = int(raw_max_length)
        except (ValueError, TypeError):
            max_length = -1

        if not target:
            flash("Enter a lab-only target password.", "danger")
        elif max_length < 1 or max_length > 4:
            flash("Maximum length is limited to 1 to 4 characters for classroom simulation.", "danger")
        elif charset not in CHARSETS:
            flash("Unsupported character set selected.", "danger")
        else:
            try:
                result = bounded_bruteforce(target, max_length, charset)
                ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                target_analysis = analyze_password(target)

                HISTORY.append({
                    "test_type": "Brute-Force Sim",
                    "timestamp": ts,
                    "strength": target_analysis["strength"],
                    "entropy": target_analysis["entropy"],
                    "length": len(target),
                    "common_word_match": target_analysis["dictionary_match"],
                    "dictionary_match": False,
                    "bruteforce_match": result["found"],
                    "severity": target_analysis["severity"],
                    "attempts": result["attempts"],
                    "rate": result["rate"],
                    "search_space": result["search_space"],
                    "estimated_worst_case": result["estimated_worst_case"],
                    "details": f"Charset: {charset}, MaxLen: {max_length}",
                })
            except ValueError as ve:
                flash(str(ve), "danger")
    return render_template("brute_force.html", result=result)


@app.route("/hash-inspector", methods=["GET", "POST"])
def hash_inspector():
    records = None
    if request.method == "POST":
        lab_text = request.form.get("lab_text", "")
        uploaded = request.files.get("lab_file")
        if uploaded and uploaded.filename:
            filename = uploaded.filename.strip()
            suffix = Path(filename).suffix.lower()
            if suffix not in ALLOWED_EXTENSIONS:
                flash("Invalid file format. Only .txt, .log, .lst, and .csv files are allowed.", "danger")
                return render_template("hash_inspector.html", records=None)
            try:
                content_bytes = uploaded.read()
                lab_text = content_bytes.decode("utf-8", errors="replace")
            except Exception as e:
                flash(f"Failed to read uploaded file: {e}", "danger")
                return render_template("hash_inspector.html", records=None)

        if not lab_text.strip():
            flash("Paste or upload a lab-only hash export.", "danger")
        else:
            try:
                records = parse_lab_hash_file(lab_text)
                ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                high_conf = sum(1 for r in records if r.get("confidence") == "High")
                med_conf = sum(1 for r in records if r.get("confidence") == "Medium")
                HISTORY.append({
                    "test_type": "Hash Inspection",
                    "timestamp": ts,
                    "strength": "Strong" if high_conf > 0 else "Medium",
                    "entropy": "",
                    "length": "",
                    "common_word_match": False,
                    "dictionary_match": False,
                    "bruteforce_match": False,
                    "severity": "Low" if (high_conf or med_conf) else "Medium",
                    "attempts": len(records),
                    "rate": "",
                    "search_space": "",
                    "estimated_worst_case": "",
                    "details": f"Analyzed {len(records)} hash records ({high_conf} high-confidence)",
                })
                flash(f"Analyzed {len(records)} lab records without accessing the local credential store.", "success")
            except Exception as e:
                flash(f"Error parsing hash data: {e}", "danger")
    return render_template("hash_inspector.html", records=records)


@app.route("/reports")
def reports():
    report_files = sorted(REPORT_DIR.glob("*"), key=lambda p: p.stat().st_mtime, reverse=True)
    return render_template("reports.html", reports=report_files)


@app.route("/reports/generate", methods=["POST"])
def generate_report():
    payload = {
        "metadata": {
            "auditor": "Aniket",
            "suite": "Password Security Auditing & Controlled Attack Simulation Suite",
            "version": "2.0.0",
            "exported_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        },
        "summary": {
            "total_tests": len(HISTORY),
            "weak": sum(1 for x in HISTORY if x.get("strength") == "Weak"),
            "medium": sum(1 for x in HISTORY if x.get("strength") == "Medium"),
            "strong": sum(1 for x in HISTORY if x.get("strength") == "Strong"),
            "common_word_matches": sum(1 for x in HISTORY if x.get("common_word_match", False)),
            "dictionary_matches": sum(1 for x in HISTORY if x.get("dictionary_match", False)),
            "bruteforce_matches": sum(1 for x in HISTORY if x.get("bruteforce_match", False)),
            "high_risk": sum(1 for x in HISTORY if x.get("severity") == "High"),
        },
        "tests": HISTORY,
    }
    json_path = REPORT_DIR / "security_audit_report.json"
    csv_path = REPORT_DIR / "security_audit_results.csv"
    try:
        save_report_json(payload, json_path)
        save_report_csv(HISTORY, csv_path)
        flash("JSON and CSV reports generated.", "success")
    except Exception as e:
        flash(f"Failed to generate reports: {e}", "danger")
    return redirect(url_for("reports"))


@app.route("/clear-history", methods=["POST"])
def clear_history():
    HISTORY.clear()
    flash("Dashboard test history cleared.", "success")
    return redirect(url_for("dashboard"))


if __name__ == "__main__":
    app.run(debug=False)
