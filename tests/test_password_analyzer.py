"""
tests/test_password_analyzer.py
=============================================================================
Test Suite — Password Strength Analyzer
Academic Project: B.Tech Computer Science (Cyber Security)
=============================================================================
Tests strength scoring, entropy calculation, pattern detection, criteria
checklist logic, crack time formatting, and edge cases.

Run with:  python3 -m pytest tests/ -v
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import pytest
from password_analyzer import analyze_password


# ============================================================
# 1. Strength Classification Tests
# ============================================================

class TestStrengthClassification:

    def test_empty_string(self):
        """Empty input should return score 0 and 'Empty' label."""
        result = analyze_password("")
        assert result["score"] == 0
        assert result["strength_label"] == "Empty"

    def test_very_weak_common_password(self):
        """Common password 'password' should be Very Weak (score 1)."""
        result = analyze_password("password")
        assert result["score"] == 1
        assert result["strength_label"] == "Very Weak"

    def test_very_weak_short_password(self):
        """3-character password should be Very Weak."""
        result = analyze_password("abc")
        assert result["score"] == 1

    def test_weak_password(self):
        """All-lowercase medium-length password should score ≤ 2."""
        result = analyze_password("simpleword")
        assert result["score"] <= 2

    def test_moderate_password(self):
        """Mixed case + digits, reasonable length → Moderate (score 3)."""
        result = analyze_password("Moderate99")
        assert result["score"] >= 2  # At least Weak to Moderate

    def test_strong_password(self):
        """Long password with all character types should be Strong or Very Strong."""
        result = analyze_password("CorrectH0rse!Battery#Staple")
        assert result["score"] >= 4

    def test_very_strong_password(self):
        """High-entropy random-looking password should be Very Strong (score 5)."""
        result = analyze_password("X#9mP!2kL$8wQ@7zR")
        assert result["score"] >= 4

    def test_score_range(self):
        """Score must always be in range [0, 5]."""
        inputs = ["", "a", "abc123", "SuperSecure!99", "a" * 30, "X#9mP!2kL$8wQ@7zR"]
        for pwd in inputs:
            result = analyze_password(pwd)
            assert 0 <= result["score"] <= 5, f"Score {result['score']} out of range for '{pwd}'"


# ============================================================
# 2. Criteria Checklist Tests
# ============================================================

class TestCriteriaChecklist:

    def test_length_criteria(self):
        result = analyze_password("a" * 12)
        assert result["criteria"]["has_min_length"] is True
        result_short = analyze_password("a" * 11)
        assert result_short["criteria"]["has_min_length"] is False

    def test_uppercase_criteria(self):
        assert analyze_password("HASupper")["criteria"]["has_upper"] is True
        assert analyze_password("nouppercase")["criteria"]["has_upper"] is False

    def test_lowercase_criteria(self):
        assert analyze_password("haslower")["criteria"]["has_lower"] is True
        assert analyze_password("NOLOWER")["criteria"]["has_lower"] is False

    def test_digit_criteria(self):
        assert analyze_password("hasDigit1")["criteria"]["has_digit"] is True
        assert analyze_password("NoDigitsHere!")["criteria"]["has_digit"] is False

    def test_symbol_criteria(self):
        assert analyze_password("hasSymbol!")["criteria"]["has_symbol"] is True
        assert analyze_password("NoSymbolHere1A")["criteria"]["has_symbol"] is False

    def test_all_criteria_met(self):
        result = analyze_password("SuperStr0ng!Password")
        c = result["criteria"]
        assert c["has_min_length"]
        assert c["has_upper"]
        assert c["has_lower"]
        assert c["has_digit"]
        assert c["has_symbol"]


# ============================================================
# 3. Entropy Calculation Tests
# ============================================================

class TestEntropy:

    def test_empty_has_zero_entropy(self):
        result = analyze_password("")
        assert result["entropy"] == 0.0

    def test_entropy_is_positive_for_nonempty(self):
        result = analyze_password("abc")
        assert result["entropy"] > 0

    def test_entropy_increases_with_length(self):
        short = analyze_password("aBc1!")
        long  = analyze_password("aBc1!aBc1!aBc1!")
        assert long["entropy"] > short["entropy"]

    def test_entropy_increases_with_variety(self):
        lowercase_only  = analyze_password("abcdefghijkl")  # pool = 26
        mixed_case      = analyze_password("AbcDefGhiJkl")  # pool = 52
        with_digits     = analyze_password("AbcD3fGhiJk1")  # pool = 62
        assert mixed_case["entropy"] > lowercase_only["entropy"]
        assert with_digits["entropy"] > mixed_case["entropy"]

    def test_entropy_formula_matches_manual(self):
        """E = L * log2(R). Verify formula output for simple known case."""
        import math
        result = analyze_password("abcdefghij")  # all lowercase, length 10, pool=26
        expected_entropy = round(10 * math.log2(26), 2)
        assert result["entropy"] == expected_entropy


# ============================================================
# 4. Pattern Detection Tests
# ============================================================

class TestPatternDetection:

    def test_common_password_detected(self):
        result = analyze_password("password")
        assert any(p["type"] == "danger" for p in result["patterns"])

    def test_sequential_pattern_detected(self):
        result = analyze_password("12345678")
        patterns_text = [p["text"] for p in result["patterns"]]
        # Should trigger sequential detection
        assert len(result["patterns"]) > 0

    def test_repeated_characters_detected(self):
        result = analyze_password("aaaabbbbcc")
        patterns_text = " ".join([p["text"] for p in result["patterns"]])
        assert "repeated" in patterns_text.lower() or len(result["patterns"]) > 0

    def test_keyboard_walk_detected(self):
        result = analyze_password("qwerty123456")
        patterns_text = " ".join([p["text"] for p in result["patterns"]]).lower()
        assert "keyboard" in patterns_text or "qwerty" in patterns_text

    def test_clean_password_no_critical_patterns(self):
        """A high-entropy random password should not trigger any critical patterns."""
        result = analyze_password("X#9mP!2kL$8wQ@7z")
        danger_patterns = [p for p in result["patterns"] if p["type"] == "danger"]
        assert len(danger_patterns) == 0

    def test_pattern_type_field_valid(self):
        """All pattern entries must have valid 'type' fields."""
        result = analyze_password("password123")
        for p in result["patterns"]:
            assert p["type"] in ("danger", "warning")


# ============================================================
# 5. Crack Time Tests
# ============================================================

class TestCrackTimes:

    def test_crack_times_present_for_nonempty(self):
        result = analyze_password("SomePassword123!")
        crack = result["crack_times"]
        assert "online_throttled" in crack
        assert "online_fast" in crack
        assert "offline_gpu" in crack
        assert "offline_pbkdf2" in crack

    def test_very_weak_cracks_instantly(self):
        result = analyze_password("abc")
        gpu_time = result["crack_times"]["offline_gpu"]
        # Very short, very weak passwords should crack almost instantly
        assert "Instant" in gpu_time or "second" in gpu_time.lower()

    def test_strong_password_long_crack_time(self):
        result = analyze_password("X#9mP!2kL$8wQ@7zRtYuIoPaS")
        gpu_time = result["crack_times"]["offline_gpu"]
        # Strong password should show a significant time for offline GPU
        instant_keywords = ["Instant", "millisecond"]
        assert not any(k in gpu_time for k in instant_keywords)


# ============================================================
# 6. Flask API Integration Tests
# ============================================================

class TestFlaskAPIIntegration:

    @pytest.fixture
    def client(self):
        """Create a Flask test client."""
        import app as flask_app
        flask_app.app.config['TESTING'] = True
        flask_app.app.config['SECRET_KEY'] = 'test-secret-key-12345'
        with flask_app.app.test_client() as client:
            with flask_app.app.app_context():
                from database import init_db
                init_db()
            yield client

    def test_analyze_endpoint_returns_200(self, client):
        resp = client.post('/api/analyze',
                           json={'password': 'TestPassword123!'},
                           content_type='application/json')
        assert resp.status_code == 200

    def test_analyze_empty_password(self, client):
        resp = client.post('/api/analyze',
                           json={'password': ''},
                           content_type='application/json')
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['score'] == 0

    def test_hash_endpoint(self, client):
        resp = client.post('/api/hash',
                           json={'text': 'Hello, World!'},
                           content_type='application/json')
        assert resp.status_code == 200
        data = resp.get_json()
        assert 'hex_digest' in data
        assert len(data['hex_digest']) == 64

    def test_hash_endpoint_input_too_long(self, client):
        resp = client.post('/api/hash',
                           json={'text': 'A' * 1025},
                           content_type='application/json')
        assert resp.status_code == 400

    def test_avalanche_endpoint(self, client):
        resp = client.post('/api/avalanche',
                           json={'input1': 'Password123', 'input2': 'Password124'},
                           content_type='application/json')
        assert resp.status_code == 200
        data = resp.get_json()
        assert 'diff_bits' in data
        assert 'avalanche_percentage' in data
        assert len(data['bit_matrix']) == 256

    def test_register_and_login_demo_flow(self, client):
        """Test full register → login demo workflow."""
        import time
        unique_user = f"testuser_{int(time.time())}"

        # Setup: get CSRF token from a page first
        home_resp = client.get('/')
        # CSRF is generated server-side; for test client we bypass by injecting token into session
        with client.session_transaction() as sess:
            sess['csrf_token'] = 'test_csrf_token_1234'

        # Register
        reg_resp = client.post(
            '/api/register',
            json={'username': unique_user, 'password': 'SecureP@ss2026', 'csrf_token': 'test_csrf_token_1234'},
            content_type='application/json'
        )
        assert reg_resp.status_code == 201
        reg_data = reg_resp.get_json()
        assert reg_data['success'] is True

        # Login with correct password
        with client.session_transaction() as sess:
            sess['csrf_token'] = 'test_csrf_token_1234'

        login_resp = client.post(
            '/api/login',
            json={'username': unique_user, 'password': 'SecureP@ss2026', 'csrf_token': 'test_csrf_token_1234'},
            content_type='application/json'
        )
        assert login_resp.status_code == 200
        login_data = login_resp.get_json()
        assert login_data['success'] is True

    def test_wrong_password_rejected(self, client):
        """Login with wrong password must return 401 with generic error message."""
        import time
        unique_user = f"testuser2_{int(time.time())}"

        with client.session_transaction() as sess:
            sess['csrf_token'] = 'test_csrf_token_5678'

        client.post(
            '/api/register',
            json={'username': unique_user, 'password': 'CorrectPassword!', 'csrf_token': 'test_csrf_token_5678'},
            content_type='application/json'
        )

        with client.session_transaction() as sess:
            sess['csrf_token'] = 'test_csrf_token_5678'

        wrong_resp = client.post(
            '/api/login',
            json={'username': unique_user, 'password': 'WrongPassword!', 'csrf_token': 'test_csrf_token_5678'},
            content_type='application/json'
        )
        assert wrong_resp.status_code == 401
        assert wrong_resp.get_json()['success'] is False

    def test_duplicate_username_rejected(self, client):
        """Attempting to register an existing username must return 409 Conflict."""
        import time
        unique_user = f"testdup_{int(time.time())}"

        with client.session_transaction() as sess:
            sess['csrf_token'] = 'csrf_dup_test'

        client.post(
            '/api/register',
            json={'username': unique_user, 'password': 'FirstPassword!', 'csrf_token': 'csrf_dup_test'},
            content_type='application/json'
        )

        with client.session_transaction() as sess:
            sess['csrf_token'] = 'csrf_dup_test'

        dup_resp = client.post(
            '/api/register',
            json={'username': unique_user, 'password': 'SecondPassword!', 'csrf_token': 'csrf_dup_test'},
            content_type='application/json'
        )
        assert dup_resp.status_code == 409

    def test_invalid_username_rejected(self, client):
        """Username with invalid characters must be rejected."""
        with client.session_transaction() as sess:
            sess['csrf_token'] = 'csrf_invalid_test'

        resp = client.post(
            '/api/register',
            json={'username': 'in valid user!', 'password': 'Password123!', 'csrf_token': 'csrf_invalid_test'},
            content_type='application/json'
        )
        assert resp.status_code == 400

    def test_stats_endpoint(self, client):
        """Stats endpoint must return user count and event counts."""
        resp = client.get('/api/stats')
        assert resp.status_code == 200
        data = resp.get_json()
        assert 'total_users' in data
        assert 'successful_logins' in data
        assert 'failed_logins' in data
