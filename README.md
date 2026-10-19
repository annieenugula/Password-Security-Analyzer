# Password Security Analyzer Using Cryptographic Hash Functions

> **Academic Project** — B.Tech Computer Science (Cyber Security)

An interactive web application demonstrating password security principles, cryptographic hash functions, salted key derivation, and authenticated login simulation — built with **Python Flask** and standard library cryptography (`hashlib`, `secrets`, `hmac`).

---

## 🚀 Quick Start (5 minutes)

### 1. Clone / Navigate to the Project

```bash
cd /path/to/Hash_crp
```

### 2. Create and Activate a Virtual Environment (recommended)

```bash
python3 -m venv venv
source venv/bin/activate          # macOS / Linux
venv\Scripts\activate             # Windows CMD
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure Environment Variables

```bash
cp .env.example .env
# Edit .env and set your own FLASK_SECRET_KEY
```

Generate a secure secret key:
```bash
python3 -c "import secrets; print(secrets.token_hex(32))"
```

Set the environment variable:
```bash
export FLASK_SECRET_KEY="your-generated-secret-key"
# Optional: configure PBKDF2 iterations (default 100,000)
export PBKDF2_ITERATIONS=100000
```

### 5. Run the Flask Application

```bash
python3 app.py
```

Open your browser at: **http://localhost:5055**

---

## 🧪 Running the Test Suite

```bash
python3 -m pytest tests/ -v
```

To run with coverage report:
```bash
pip install pytest-cov
python3 -m pytest tests/ -v --cov=. --cov-report=term-missing
```

---

## 📁 Project Structure

```
Hash_crp/
├── app.py                          # Flask application, all API routes
├── crypto_utils.py                 # SHA-256, PBKDF2-HMAC-SHA-256, avalanche, salting
├── password_analyzer.py            # Entropy, pattern detection, crack time estimation
├── database.py                     # SQLite operations with parameterized queries
├── requirements.txt
├── .env.example                    # Environment variable template
├── .gitignore
├── README.md
├── instance/
│   └── security_analyzer.db        # Auto-created SQLite database (gitignored)
├── templates/
│   ├── base.html                   # Layout with nav, footer, toast, theme toggle
│   ├── index.html                  # Home / Dashboard
│   ├── analyzer.html               # Real-time password strength analysis
│   ├── hash_generator.html         # SHA-256 demo
│   ├── avalanche.html              # Avalanche effect visualizer
│   ├── register.html               # PBKDF2 secure registration demo
│   ├── login.html                  # Authentication verification demo
│   ├── dashboard.html              # Security statistics
│   └── about.html                  # Educational cryptography reference
├── static/
│   ├── css/style.css               # Dark/light theme, all component styles
│   └── js/script.js                # Shared JS: theme, API helper, toasts
└── tests/
    ├── __init__.py
    ├── test_crypto.py              # Tests for SHA-256, PBKDF2, salt, avalanche
    └── test_password_analyzer.py   # Tests for strength scoring + Flask API
```

---

## 🔐 Security Architecture

| Layer | Implementation | Notes |
|-------|----------------|-------|
| Password Hashing | PBKDF2-HMAC-SHA-256 | 100,000 iterations, 128-bit salt |
| Salt Generation | `secrets.token_hex(16)` | OS CSPRNG |
| Hash Comparison | `hmac.compare_digest()` | Constant-time, prevents timing attacks |
| Database Queries | SQLite `?` parameterized | Prevents SQL injection |
| CSRF Protection | Session token validated per POST | Rejects forged cross-site requests |
| Secret Key | Read from `FLASK_SECRET_KEY` env var | Never hardcoded in source |
| Password Storage | Only derived hash + salt + params | Plaintext never written to disk |
| Error Messages | Generic ("Invalid credentials") | Prevents username enumeration |

---

## 📚 Application Modules

| Module | URL | Description |
|--------|-----|-------------|
| Home | `/` | Dashboard with module cards and statistics |
| Password Analyzer | `/analyzer` | Real-time entropy, criteria, and crack times |
| SHA-256 Lab | `/hash-generator` | Determinism and one-way hash demonstration |
| Avalanche Effect | `/avalanche` | 256-bit diffusion matrix and hex char diff |
| Registration Demo | `/register` | PBKDF2 secure account creation |
| Login Demo | `/login` | Constant-time hash verification |
| Security Dashboard | `/dashboard` | Non-sensitive authentication event stats |
| Learn | `/about` | Cryptographic fundamentals, attack types, algorithm comparison |

---

## 🛠️ API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/analyze` | Password strength analysis |
| `POST` | `/api/hash` | SHA-256 hash generation |
| `POST` | `/api/avalanche` | Avalanche effect analysis |
| `POST` | `/api/register` | Demo user registration |
| `POST` | `/api/login` | Password verification |
| `GET`  | `/api/stats` | Aggregated event statistics |

---

## ⚙️ Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `FLASK_SECRET_KEY` | *Random on start* | Session encryption key (set this in production!) |
| `PBKDF2_ITERATIONS` | `100000` | Work factor for PBKDF2. Increase as hardware improves. |
| `PORT` | `5055` | Server port |
| `FLASK_DEBUG` | `1` | Debug mode. Set to `0` in production. |

**NIST SP 800-132 recommendation (2023):** Minimum **600,000 iterations** for PBKDF2-SHA-256 in production systems.

---

## 🏫 Academic Information

| Field | Value |
|-------|-------|
| **Project Title** | Password Security Analyzer Using Cryptographic Hash Functions |
| **Student Name** | [Student Name Placeholder] |
| **Roll Number** | [Roll No. Placeholder] |
| **Faculty Supervisor** | [Dr./Prof. Supervisor Name] |
| **Department** | Dept. of Computer Science & Engineering — Cyber Security |
| **Institution** | [College / University Name] |
| **Academic Year** | 2025 – 2026 |

---

## 📄 License

This project is created for academic purposes only. All cryptographic operations use Python standard library (`hashlib`, `secrets`, `hmac`). No real user credentials should be stored in this system.
