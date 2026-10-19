"""
database.py
=============================================================================
Database Initialization and Operations for Password Security Analyzer
Academic Project: B.Tech Computer Science (Cyber Security)
=============================================================================
Uses Python standard library sqlite3. All queries are parameterized to prevent
SQL injection. Passwords and sensitive credentials are NEVER stored in plaintext
and are NEVER logged.
"""

import sqlite3
import os
from datetime import datetime
from typing import Optional, Dict, Any

# Database file path (stored inside the project folder)
DB_PATH = os.path.join(os.path.dirname(__file__), 'instance', 'security_analyzer.db')


def _get_connection() -> sqlite3.Connection:
    """
    Create and return a new database connection with Row factory enabled.
    Row factory allows accessing columns by name (dict-like interface).
    """
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    # Enable Write-Ahead Logging for better concurrency
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db() -> None:
    """
    Initialize the SQLite database by creating required tables.
    Called automatically on first application startup.

    Schema:
    - users:  Demo accounts for the registration/login demonstration.
    - auth_events: Minimal, non-sensitive audit log of authentication events.
                   NOTE: Passwords are NEVER recorded in this table.
    """
    with _get_connection() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                username        TEXT    NOT NULL UNIQUE COLLATE NOCASE,
                password_hash   TEXT    NOT NULL,
                salt            TEXT    NOT NULL,
                algorithm       TEXT    NOT NULL DEFAULT 'PBKDF2-HMAC-SHA-256',
                iteration_count INTEGER NOT NULL DEFAULT 100000,
                created_at      TEXT    NOT NULL
            );

            -- Minimal non-sensitive audit log.
            -- Records only event type, username, outcome, and timestamp.
            -- Passwords, hashes, and salts are NEVER stored here.
            CREATE TABLE IF NOT EXISTS auth_events (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type  TEXT    NOT NULL,   -- 'register' or 'login'
                username    TEXT    NOT NULL,
                success     INTEGER NOT NULL,   -- 1 = success, 0 = failure
                timestamp   TEXT    NOT NULL,
                ip_address  TEXT                -- Optional: client IP (anonymized or omitted)
            );
        """)


# ---------------------------------------------------------------------------
# User Operations
# ---------------------------------------------------------------------------

def create_user(username: str, password_hash: str, salt: str,
                algorithm: str, iteration_count: int) -> Dict[str, Any]:
    """
    Insert a new demo user into the database.

    SECURITY: Only the derived hash, salt, and algorithm parameters are stored.
    The original plaintext password is NEVER written to the database.

    Args:
        username (str): Chosen username (must be unique, case-insensitive).
        password_hash (str): PBKDF2-derived hexadecimal hash string.
        salt (str): Unique cryptographically random salt (hex string).
        algorithm (str): Algorithm label for human-readable metadata.
        iteration_count (int): Iteration count / work factor used during derivation.

    Returns:
        dict: {'success': True/False, 'message': str, 'user_id': int or None}
    """
    created_at = datetime.utcnow().isoformat() + "Z"
    try:
        with _get_connection() as conn:
            cursor = conn.execute(
                """
                INSERT INTO users (username, password_hash, salt, algorithm, iteration_count, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (username, password_hash, salt, algorithm, iteration_count, created_at)
            )
            conn.commit()
            return {'success': True, 'message': 'Account created.', 'user_id': cursor.lastrowid}
    except sqlite3.IntegrityError:
        return {'success': False, 'message': 'Username already exists. Please choose a different username.', 'user_id': None}
    except sqlite3.Error as e:
        return {'success': False, 'message': 'A database error occurred.', 'user_id': None}


def get_user_by_username(username: str) -> Optional[sqlite3.Row]:
    """
    Retrieve a user record by username (case-insensitive lookup).

    Args:
        username (str): Username to look up.

    Returns:
        sqlite3.Row with columns: id, username, password_hash, salt,
                                  algorithm, iteration_count, created_at.
        Returns None if not found.
    """
    with _get_connection() as conn:
        row = conn.execute(
            "SELECT * FROM users WHERE username = ? COLLATE NOCASE",
            (username,)
        ).fetchone()
    return row


def get_total_user_count() -> int:
    """Return total number of registered demo accounts."""
    with _get_connection() as conn:
        result = conn.execute("SELECT COUNT(*) FROM users").fetchone()
    return result[0] if result else 0


# ---------------------------------------------------------------------------
# Audit Event Operations
# ---------------------------------------------------------------------------

def log_auth_event(event_type: str, username: str, success: bool,
                   ip_address: Optional[str] = None) -> None:
    """
    Record a minimal, non-sensitive authentication event in the audit log.

    SECURITY: Only event type, username, outcome, and timestamp are stored.
    Passwords, password hashes, and salts are NEVER recorded here.

    Args:
        event_type (str): 'register' or 'login'.
        username (str): The username involved in the event.
        success (bool): Whether the authentication event succeeded.
        ip_address (str, optional): Client IP address (anonymize or omit in production).
    """
    timestamp = datetime.utcnow().isoformat() + "Z"
    try:
        with _get_connection() as conn:
            conn.execute(
                """
                INSERT INTO auth_events (event_type, username, success, timestamp, ip_address)
                VALUES (?, ?, ?, ?, ?)
                """,
                (event_type, username, int(success), timestamp, ip_address)
            )
            conn.commit()
    except sqlite3.Error:
        pass  # Audit log failure must not interrupt the main authentication flow


def get_auth_event_stats() -> Dict[str, int]:
    """
    Return aggregated, non-sensitive authentication statistics for the dashboard.

    Returns:
        dict: Counts of total events, successful logins, failed logins,
              registrations, failed registrations.
    """
    with _get_connection() as conn:
        stats = conn.execute("""
            SELECT
                SUM(CASE WHEN event_type = 'login'    AND success = 1 THEN 1 ELSE 0 END) AS successful_logins,
                SUM(CASE WHEN event_type = 'login'    AND success = 0 THEN 1 ELSE 0 END) AS failed_logins,
                SUM(CASE WHEN event_type = 'register' AND success = 1 THEN 1 ELSE 0 END) AS successful_registrations,
                SUM(CASE WHEN event_type = 'register' AND success = 0 THEN 1 ELSE 0 END) AS failed_registrations,
                COUNT(*) AS total_events
            FROM auth_events
        """).fetchone()

    if not stats:
        return {
            "successful_logins": 0,
            "failed_logins": 0,
            "successful_registrations": 0,
            "failed_registrations": 0,
            "total_events": 0,
        }

    return dict(stats)
