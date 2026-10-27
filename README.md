<div align="center">

# CNS SecureAudit

**A Flask toolkit for password strength analysis, hash identification and bounded attack simulation.**

![Python](https://img.shields.io/badge/python-3.10-3b4252?style=flat-square&logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/flask-web%20app-3b4252?style=flat-square&logo=flask&logoColor=white)
![Plotly](https://img.shields.io/badge/plotly-visualization-3b4252?style=flat-square)
![Status](https://img.shields.io/badge/status-educational-3b4252?style=flat-square)

[Overview](#-overview) · [Features](#-features) · [Stack](#-tech-stack) · [Setup](#-setup) · [Usage](#-usage) · [Structure](#-project-structure)

</div>

<br>

## 🔐 Overview

CNS SecureAudit is an educational toolkit for exploring password security and common auditing techniques through a web dashboard. It combines password analysis, hash processing and attack simulation in one place, without touching real authentication systems or OS credential stores.

> [!IMPORTANT]
> Scores and entropy estimates are heuristics, not guarantees. Use only passwords and hashes you own or are authorized to test.

<br>

## 🧩 Features

| Tool | What it does |
|---|---|
| **Password analyzer** | Rates a password Weak, Medium or Strong from length, character mix, entropy and common patterns, with recommendations. |
| **Dictionary generator** | Builds candidate passwords from a name, year or keyword, with case variants, leetspeak and common suffixes. |
| **SHA-256 hash simulator** | Hashes each candidate and compares it against a target hash, reporting a match and attempt count. |
| **Bounded brute-force simulator** | Generates candidates up to a set length and character set, hashes each and reports attempts, time and rate. Capped at 4 characters in the web interface. |
| **Hash format inspector** | Classifies a hash by prefix and length (yescrypt, SHA-512 crypt, SHA-256 crypt, bcrypt, MD5 crypt, raw hex). Some raw hex digests cannot be identified uniquely. |
| **Audit reports** | Exports results to JSON or CSV, covering timestamps, test type, strength, entropy, attempts and search-space estimates. |
| **Dashboard** | Session-level history and summary statistics. Metrics reflect only the operations the app records. |

<br>

## 🧰 Tech stack

Python, Flask, HTML, CSS, JavaScript, Plotly, `hashlib`, `itertools`, `unittest`

<br>

## ⚙️ Setup

```bash
git clone https://github.com/aniiiket08/cns-secureaudit.git
cd cns-secureaudit
```

**Virtual environment**

```bash
# Windows
python -m venv venv
venv\Scripts\activate

# Linux / macOS
python3 -m venv venv
source venv/bin/activate
```

**Install and run**

```bash
python -m pip install -r requirements.txt
python app.py
```

Open `http://127.0.0.1:5000`.

<br>

## ▶️ Usage

1. Open the dashboard.
2. Check a password's strength in the analyzer.
3. Build a candidate wordlist in the dictionary generator.
4. Test candidates against a hash in the hash simulator.
5. Run the bounded brute-force simulator on a restricted search space.
6. Classify sample hashes in the format inspector.
7. Review and export audit reports.

Use synthetic passwords and self-generated hashes for demonstrations.

**Tests**

```bash
python -m unittest discover -s tests -v
```

Unit tests cover the core modules, not every Flask route, upload or report export.

<br>

## 📁 Project structure

```
.
├── app.py
├── modules/
│   ├── analyzer.py
│   ├── dictionary_generator.py
│   ├── hash_simulator.py
│   ├── brute_force.py
│   ├── hash_formats.py
│   └── report.py
├── templates/
│   ├── base.html
│   ├── dashboard.html
│   ├── analyzer.html
│   ├── dictionary.html
│   ├── hash_simulator.html
│   ├── brute_force.html
│   ├── hash_inspector.html
│   └── reports.html
├── static/
│   ├── css/style.css
│   └── js/dashboard.js
├── tests/
│   └── test_modules.py
├── data/                  generated files, not present in a fresh checkout
├── reports/               generated files, not present in a fresh checkout
├── requirements.txt
└── README.md
```

<br>

## ⚠️ Security notes

- Educational tool, not a production password manager.
- SHA-256 demonstrates hash matching. It is not a password-storage scheme. Production systems need Argon2id, scrypt or bcrypt with proper salting.
- Session history is in-memory and clears on restart.
- Before any deployment, add a strong secret key, CSRF protection, input validation and a review of session and report handling.

<br>

## 📄 Disclaimer

For educational use, coursework and authorized security testing only. Do not use it to access, test or compromise accounts without explicit permission.
