"""
Authentication, Cryptography, and Session management.
Uses PBKDF2-HMAC-SHA256 for secure password hashing and RFC 7519 HS256 JWT tokens.
"""
import hashlib
import hmac
import base64
import json
import time
import secrets
import re
from datetime import datetime
from database import get_db, init_db

JWT_SECRET = "ai_prep_master_jwt_secret_key_prod_v1_2026_9882348"
JWT_EXPIRATION_DEFAULT = 3600 * 24       # 24 hours
JWT_EXPIRATION_REMEMBER = 3600 * 24 * 30  # 30 days

def hash_password(password: str, salt: str = None) -> tuple[str, str]:
    """Generates PBKDF2-HMAC-SHA256 hash with 100,000 rounds and random 32-hex salt."""
    if not salt:
        salt = secrets.token_hex(16)
    hashed = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        100000
    )
    return hashed.hex(), salt

def verify_password(password: str, hashed: str, salt: str) -> bool:
    """Verifies a plaintext password against the stored PBKDF2 hash using constant-time comparison."""
    if not password or not hashed or not salt:
        return False
    calc_hash, _ = hash_password(password, salt)
    return hmac.compare_digest(calc_hash, hashed)

def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")

def b64url_decode(s: str) -> bytes:
    padding = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + padding)

def create_jwt(payload: dict, expires_in: int = JWT_EXPIRATION_DEFAULT) -> str:
    """Creates a signed HS256 JWT token."""
    header = {"alg": "HS256", "typ": "JWT"}
    payload = payload.copy()
    now = int(time.time())
    payload["iat"] = now
    payload["exp"] = now + expires_in
    payload["jti"] = secrets.token_hex(8)

    h_bytes = json.dumps(header, separators=(",", ":")).encode("utf-8")
    p_bytes = json.dumps(payload, separators=(",", ":")).encode("utf-8")

    h_b64 = b64url_encode(h_bytes)
    p_b64 = b64url_encode(p_bytes)

    signing_input = f"{h_b64}.{p_b64}".encode("utf-8")
    sig = hmac.new(JWT_SECRET.encode("utf-8"), signing_input, hashlib.sha256).digest()
    sig_b64 = b64url_encode(sig)

    return f"{h_b64}.{p_b64}.{sig_b64}"

def decode_jwt(token: str) -> dict | None:
    """Decodes and validates signature and expiration of an HS256 JWT token."""
    if not token or not isinstance(token, str):
        return None
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        h_b64, p_b64, sig_b64 = parts
        signing_input = f"{h_b64}.{p_b64}".encode("utf-8")
        expected_sig = hmac.new(JWT_SECRET.encode("utf-8"), signing_input, hashlib.sha256).digest()
        actual_sig = b64url_decode(sig_b64)
        if not hmac.compare_digest(expected_sig, actual_sig):
            return None
        payload = json.loads(b64url_decode(p_b64).decode("utf-8"))
        if payload.get("exp", 0) < time.time():
            return None
        return payload
    except Exception:
        return None

def validate_email(email: str) -> bool:
    if not email:
        return False
    pattern = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
    return bool(re.match(pattern, email.strip()))

def calculate_password_strength(password: str) -> dict:
    score = 0
    feedback = []
    if len(password) >= 8:
        score += 1
    else:
        feedback.append("At least 8 characters")

    if re.search(r"[A-Z]", password):
        score += 1
    else:
        feedback.append("At least one uppercase letter")

    if re.search(r"[0-9]", password):
        score += 1
    else:
        feedback.append("At least one digit")

    if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        score += 1
    else:
        feedback.append("At least one special symbol")

    labels = ["Weak", "Fair", "Good", "Strong", "Very Strong"]
    return {
        "score": score,
        "max_score": 4,
        "label": labels[score],
        "feedback": feedback
    }

def seed_default_accounts():
    """Initializes admin and demo student accounts with secure PBKDF2 hashed credentials."""
    init_db()
    conn = get_db()
    cursor = conn.cursor()

    # 1. Admin Account (admin@aiinterview.com / Admin@123)
    cursor.execute("SELECT id FROM users WHERE email = ?", ("admin@aiinterview.com",))
    if not cursor.fetchone():
        pwd_hash, salt = hash_password("Admin@123")
        cursor.execute("""
            INSERT INTO users (
                name, email, phone, college, password_hash, salt, role, is_active,
                onboarded, target_role, target_companies, experience_level,
                readiness_score, streak_days, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            "Admin Director", "admin@aiinterview.com", "+1-800-555-0199", "Tech Leadership Institute",
            pwd_hash, salt, "admin", 1, 1, "Platform Administrator", "System Wide",
            "Executive Staff", 100, 45, datetime.utcnow().isoformat()
        ))

    # 2. Student Demo Account (student@demo.com / Pass@123)
    cursor.execute("SELECT id FROM users WHERE email = ?", ("student@demo.com",))
    if not cursor.fetchone():
        pwd_hash, salt = hash_password("Pass@123")
        cursor.execute("""
            INSERT INTO users (
                name, email, phone, college, password_hash, salt, role, is_active,
                onboarded, target_role, target_companies, experience_level,
                readiness_score, streak_days, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            "Alex Chen", "student@demo.com", "+1-415-555-2671", "Stanford University",
            pwd_hash, salt, "student", 1, 1, "Full Stack Engineer", "Google, Meta, Stripe",
            "Entry Level (0-2 yrs)", 84, 7, datetime.utcnow().isoformat()
        ))

    # Seed initial questions if empty
    cursor.execute("SELECT COUNT(*) as count FROM questions")
    if cursor.fetchone()["count"] == 0:
        sample_questions = [
            ("Data Structures", "Implement an LRU Cache with O(1) operations", "Hard",
             "Design a data structure that follows the constraints of a Least Recently Used (LRU) cache.",
             "Use a Doubly Linked List paired with a Hash Map for O(1) get and put operations."),
            ("Algorithms", "Longest Substring Without Repeating Characters", "Medium",
             "Given a string s, find the length of the longest substring without duplicate characters.",
             "Use a sliding window approach with two pointers and a character index hash map."),
            ("System Design", "Design a Scalable URL Shortener (TinyURL)", "Medium",
             "Design a service like TinyURL that takes long URLs and generates unique short aliases.",
             "Use Base62 encoding on unique 64-bit integer IDs generated by a distributed snowflake service."),
            ("Behavioral", "Tell me about a time you had a technical disagreement with a team member.", "Medium",
             "Demonstrate conflict resolution using data-driven decision making and empathy.",
             "Structure with STAR: Situation (differing opinions on DB schema), Task, Action (benchmarked both), Result (aligned on facts)."),
            ("CS Fundamentals", "Explain ACID properties in database management", "Easy",
             "Define Atomicity, Consistency, Isolation, and Durability with real-world examples.",
             "A: All-or-nothing transactions; C: Invariant validation; I: Concurrency isolation levels; D: Persistence to non-volatile storage.")
        ]
        for cat, title, diff, desc, sol in sample_questions:
            cursor.execute("""
                INSERT INTO questions (category, title, difficulty, description, sample_solution, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (cat, title, diff, desc, sol, datetime.utcnow().isoformat()))

    conn.commit()
    conn.close()

if __name__ == "__main__":
    seed_default_accounts()
    print("Default accounts and sample questions seeded successfully.")
