"""
app.py
=============================================================================
Flask Application Entry Point – Password Security Analyzer
Academic Project: B.Tech Computer Science (Cyber Security)
=============================================================================
Provides all backend API routes for:
- Password strength analysis (POST /api/analyze)
- SHA-256 hash demonstration (POST /api/hash)
- Avalanche effect analysis (POST /api/avalanche)
- User registration demo (POST /api/register)
- Login / password verification demo (POST /api/login)
- Dashboard statistics (GET /api/stats)

Security Practices Applied:
- Server-side input validation for every route
- CSRF token generation and validation for state-changing POST forms
- Parameterized SQL queries (via database.py)
- Constant-time password comparison (via crypto_utils.py)
- Passwords are NEVER logged, printed, or returned to the frontend
- Secret key read from environment variable (not hardcoded)
- Secure session cookie settings
"""

import os
import re
import secrets
from functools import wraps
from flask import (
    Flask, render_template, request, jsonify,
    session, redirect, url_for, abort
)

from database import init_db, create_user, get_user_by_username, get_total_user_count, log_auth_event, get_auth_event_stats
from crypto_utils import compute_sha256, compute_avalanche, derive_pbkdf2_hash, verify_pbkdf2_password, generate_salt
from password_analyzer import analyze_password

# ---------------------------------------------------------------------------
# Application Factory
# ---------------------------------------------------------------------------

app = Flask(__name__)

# Read secret key from environment variable.
# NEVER hardcode a secret key in source code.
app.secret_key = os.environ.get('FLASK_SECRET_KEY', secrets.token_hex(32))

# Configurable PBKDF2 iteration count (work factor)
PBKDF2_ITERATIONS = int(os.environ.get('PBKDF2_ITERATIONS', 100_000))

# Secure session cookie settings
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_SECURE=False,  # Set True in production with HTTPS
    PERMANENT_SESSION_LIFETIME=1800,  # 30 minutes
)

# Initialize database tables on startup
with app.app_context():
    init_db()


# ---------------------------------------------------------------------------
# CSRF Protection Helpers
# ---------------------------------------------------------------------------

def generate_csrf_token() -> str:
    """Generate and store a CSRF token in the user's session."""
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(32)
    return session['csrf_token']


def validate_csrf(token: str) -> bool:
    """Validate submitted CSRF token against the session token."""
    stored = session.get('csrf_token')
    if not stored or not token:
        return False
    return secrets.compare_digest(stored, token)


def csrf_protected(f):
    """Decorator: validate CSRF token on POST requests before processing."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if request.method == 'POST':
            token = (
                request.form.get('csrf_token') or
                request.headers.get('X-CSRF-Token') or
                request.json.get('csrf_token', '') if request.is_json else ''
            )
            if not validate_csrf(token):
                abort(403)
        return f(*args, **kwargs)
    return decorated


# ---------------------------------------------------------------------------
# Input Validation Helpers
# ---------------------------------------------------------------------------

def _validate_username(username: str):
    """
    Validate username: 3-32 characters, alphanumeric with underscores/hyphens only.
    Returns (True, '') or (False, error_message).
    """
    if not username:
        return False, "Username is required."
    if not (3 <= len(username) <= 32):
        return False, "Username must be 3 to 32 characters long."
    if not re.match(r'^[a-zA-Z0-9_\-]+$', username):
        return False, "Username may only contain letters, numbers, underscores, and hyphens."
    return True, ""


def _validate_password_input(password: str):
    """
    Validate that a password field is present and within a reasonable length.
    Does NOT enforce complexity rules here; that is the analyzer's job.
    """
    if not password:
        return False, "Password is required."
    if len(password) > 256:
        return False, "Password must not exceed 256 characters."
    return True, ""


# ---------------------------------------------------------------------------
# Page Routes (Serve HTML Templates)
# ---------------------------------------------------------------------------

@app.route('/')
def index():
    """Home / Dashboard page."""
    csrf_token = generate_csrf_token()
    stats = get_auth_event_stats()
    total_users = get_total_user_count()
    return render_template('index.html',
                           csrf_token=csrf_token,
                           stats=stats,
                           total_users=total_users)


@app.route('/analyzer')
def analyzer():
    """Password Strength Analyzer page."""
    csrf_token = generate_csrf_token()
    return render_template('analyzer.html', csrf_token=csrf_token)


@app.route('/hash-generator')
def hash_generator():
    """SHA-256 Hash Generator demonstration page."""
    csrf_token = generate_csrf_token()
    return render_template('hash_generator.html', csrf_token=csrf_token)


@app.route('/avalanche')
def avalanche():
    """Avalanche Effect Demonstration page."""
    csrf_token = generate_csrf_token()
    return render_template('avalanche.html', csrf_token=csrf_token)


@app.route('/register')
def register():
    """Secure Registration demo page."""
    csrf_token = generate_csrf_token()
    return render_template('register.html', csrf_token=csrf_token)


@app.route('/login')
def login():
    """Password Verification / Login demo page."""
    csrf_token = generate_csrf_token()
    return render_template('login.html', csrf_token=csrf_token)


@app.route('/dashboard')
def dashboard():
    """Security Dashboard page."""
    csrf_token = generate_csrf_token()
    stats = get_auth_event_stats()
    total_users = get_total_user_count()
    return render_template('dashboard.html',
                           csrf_token=csrf_token,
                           stats=stats,
                           total_users=total_users)


@app.route('/about')
def about():
    """About Cryptographic Hash Functions educational page."""
    return render_template('about.html')


# ---------------------------------------------------------------------------
# API Routes – Password Strength Analysis
# ---------------------------------------------------------------------------

@app.route('/api/analyze', methods=['POST'])
def api_analyze():
    """
    POST /api/analyze
    Analyze password strength and return structured metrics.

    Accepts: JSON { "password": "..." }
    Returns: JSON analysis object (score, entropy, criteria, patterns, suggestions, etc.)

    SECURITY: Password is processed server-side for analysis only.
    It is NEVER logged, stored, or forwarded to external services.
    """
    data = request.get_json(silent=True) or {}
    password = data.get('password', '')

    # Ensure password is a string; silently coerce
    if not isinstance(password, str):
        password = ''

    result = analyze_password(password)
    return jsonify(result)


# ---------------------------------------------------------------------------
# API Routes – SHA-256 Demonstration
# ---------------------------------------------------------------------------

@app.route('/api/hash', methods=['POST'])
def api_hash():
    """
    POST /api/hash
    Generate SHA-256 hash of a sample demonstration input.

    Accepts: JSON { "text": "..." }
    Returns: JSON with hex_digest, bit_length, char_length, algorithm.
    """
    data = request.get_json(silent=True) or {}
    text = data.get('text', '')

    if not isinstance(text, str):
        return jsonify({'error': 'Invalid input.'}), 400
    if len(text) > 1024:
        return jsonify({'error': 'Input text must not exceed 1024 characters.'}), 400

    result = compute_sha256(text)
    # Remove binary_digest from the API response (too large for most uses)
    result.pop('binary_digest', None)
    return jsonify(result)


# ---------------------------------------------------------------------------
# API Routes – Avalanche Effect
# ---------------------------------------------------------------------------

@app.route('/api/avalanche', methods=['POST'])
def api_avalanche():
    """
    POST /api/avalanche
    Compute SHA-256 hashes of two inputs and analyze bitwise differences.

    Accepts: JSON { "input1": "...", "input2": "..." }
    Returns: JSON with hash pair, bit diff count, avalanche percentage,
             char diff stream, bit matrix, and quality rating.
    """
    data = request.get_json(silent=True) or {}
    input1 = data.get('input1', '')
    input2 = data.get('input2', '')

    if not isinstance(input1, str) or not isinstance(input2, str):
        return jsonify({'error': 'Both inputs must be strings.'}), 400
    if len(input1) > 512 or len(input2) > 512:
        return jsonify({'error': 'Inputs must not exceed 512 characters each.'}), 400

    result = compute_avalanche(input1, input2)
    return jsonify(result)


# ---------------------------------------------------------------------------
# API Routes – Secure Registration Demo
# ---------------------------------------------------------------------------

@app.route('/api/register', methods=['POST'])
@csrf_protected
def api_register():
    """
    POST /api/register
    Register a new demo account using PBKDF2-HMAC-SHA-256.

    Accepts: JSON or form data { "username": "...", "password": "...", "csrf_token": "..." }
    Returns: JSON { "success": bool, "message": str }

    SECURITY:
    - Validates username and password.
    - Generates a unique cryptographic salt.
    - Derives a PBKDF2-HMAC-SHA-256 hash; plaintext password is discarded.
    - Stores only the derived hash, salt, and algorithm metadata.
    - Password is NEVER logged.
    """
    data = request.get_json(silent=True) or request.form or {}
    username = str(data.get('username', '')).strip()
    password = str(data.get('password', ''))

    # Validate inputs
    valid_u, msg_u = _validate_username(username)
    if not valid_u:
        return jsonify({'success': False, 'message': msg_u}), 400

    valid_p, msg_p = _validate_password_input(password)
    if not valid_p:
        return jsonify({'success': False, 'message': msg_p}), 400

    # Generate unique salt and derive hash
    salt = generate_salt(16)
    password_hash = derive_pbkdf2_hash(password, salt, PBKDF2_ITERATIONS)

    # Persist to database
    db_result = create_user(
        username=username,
        password_hash=password_hash,
        salt=salt,
        algorithm='PBKDF2-HMAC-SHA-256',
        iteration_count=PBKDF2_ITERATIONS
    )

    # Log audit event (no passwords recorded)
    log_auth_event('register', username, db_result['success'],
                   request.remote_addr)

    status_code = 201 if db_result['success'] else 409
    return jsonify({
        'success': db_result['success'],
        'message': db_result['message'],
        'algorithm': 'PBKDF2-HMAC-SHA-256',
        'iterations': PBKDF2_ITERATIONS,
        'salt_preview': salt[:8] + '...',  # Show only first 8 chars for education
    }), status_code


# ---------------------------------------------------------------------------
# API Routes – Login / Password Verification Demo
# ---------------------------------------------------------------------------

@app.route('/api/login', methods=['POST'])
@csrf_protected
def api_login():
    """
    POST /api/login
    Verify a candidate password against the stored PBKDF2 hash.

    Accepts: JSON or form data { "username": "...", "password": "...", "csrf_token": "..." }
    Returns: JSON { "success": bool, "message": str }

    SECURITY:
    - Retrieves stored salt and iteration count from the database.
    - Re-derives the candidate hash and compares using constant-time hmac.compare_digest.
    - Password is NEVER logged or returned in any response.
    - On failure, returns a generic message that does NOT reveal whether
      the username or password is incorrect (prevents username enumeration).
    """
    data = request.get_json(silent=True) or request.form or {}
    username = str(data.get('username', '')).strip()
    password = str(data.get('password', ''))

    # Validate inputs (generic error, not revealing which field failed)
    if not username or not password:
        return jsonify({'success': False, 'message': 'Invalid credentials.'}), 400

    # Look up user record
    user = get_user_by_username(username)

    # Perform verification (always run derive even if user not found to prevent timing attacks)
    if user:
        is_valid = verify_pbkdf2_password(
            password=password,
            stored_salt=user['salt'],
            stored_hash=user['password_hash'],
            iterations=user['iteration_count']
        )
    else:
        # Run a dummy derivation to maintain constant response time (prevent username enumeration via timing)
        dummy_salt = generate_salt(16)
        _ = derive_pbkdf2_hash(password, dummy_salt, PBKDF2_ITERATIONS)
        is_valid = False

    # Log audit event (no passwords recorded)
    log_auth_event('login', username, is_valid, request.remote_addr)

    if is_valid:
        return jsonify({
            'success': True,
            'message': f'Authentication successful. Welcome, {username}!',
            'verification_method': 'PBKDF2-HMAC-SHA-256 constant-time comparison'
        })
    else:
        return jsonify({
            'success': False,
            'message': 'Invalid username or password.'
        }), 401


# ---------------------------------------------------------------------------
# API Routes – Dashboard Statistics
# ---------------------------------------------------------------------------

@app.route('/api/stats', methods=['GET'])
def api_stats():
    """
    GET /api/stats
    Return aggregated, non-sensitive dashboard statistics.

    Returns: JSON { total_users, successful_logins, failed_logins, ... }
    """
    stats = get_auth_event_stats()
    stats['total_users'] = get_total_user_count()
    stats['pbkdf2_iterations'] = PBKDF2_ITERATIONS
    return jsonify(stats)


# ---------------------------------------------------------------------------
# Error Handlers
# ---------------------------------------------------------------------------

@app.errorhandler(400)
def bad_request(e):
    return jsonify({'error': 'Bad request.', 'details': str(e)}), 400


@app.errorhandler(403)
def forbidden(e):
    return jsonify({'error': 'Forbidden: CSRF token validation failed.'}), 403


@app.errorhandler(404)
def not_found(e):
    return render_template('index.html'), 404


@app.errorhandler(500)
def internal_error(e):
    return jsonify({'error': 'Internal server error.'}), 500


# ---------------------------------------------------------------------------
# Application Entry Point
# ---------------------------------------------------------------------------

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5055))
    # Debug mode is controlled by FLASK_DEBUG env var, NOT hardcoded
    debug_mode = os.environ.get('FLASK_DEBUG', '1') == '1'
    app.run(host='0.0.0.0', port=port, debug=debug_mode)
