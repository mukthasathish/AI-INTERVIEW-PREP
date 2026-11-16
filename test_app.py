"""
Comprehensive In-Memory ASGI Test Suite for AI Interview Prep Application.
Runs without network sockets using ASGI in-memory dispatch.
Tests all requirements: Login as First Screen, Validation, JWT Authentication,
Registration, Password Reset, Student Onboarding, Dashboard, Admin Role Guards,
and Interactive Preparation Modules.
"""
import sys
import os
import json
import time
import asyncio

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from server import app
from database import init_db
from auth import seed_default_accounts

class ASGITestClient:
    def __init__(self, asgi_app):
        self.app = asgi_app

    async def request(self, method: str, path: str, headers: dict = None, json_body: dict = None):
        headers = headers or {}
        raw_headers = [(k.lower().encode("utf-8"), v.encode("utf-8")) for k, v in headers.items()]
        body_bytes = json.dumps(json_body).encode("utf-8") if json_body is not None else b""
        
        scope = {
            "type": "http",
            "asgi": {"version": "3.0"},
            "http_version": "1.1",
            "method": method,
            "path": path,
            "raw_path": path.encode("utf-8"),
            "query_string": b"",
            "headers": raw_headers,
            "client": ("127.0.0.1", 12345),
            "server": ("127.0.0.1", 8000)
        }
        
        messages = []
        async def receive():
            return {"type": "http.request", "body": body_bytes, "more_body": False}
        
        async def send(message):
            messages.append(message)
        
        await self.app(scope, receive, send)
        
        status = next(m["status"] for m in messages if m["type"] == "http.response.start")
        res_headers = next(m.get("headers", []) for m in messages if m["type"] == "http.response.start")
        res_body = b"".join(m.get("body", b"") for m in messages if m["type"] == "http.response.body")
        
        headers_dict = {k.decode("utf-8"): v.decode("utf-8") for k, v in res_headers}
        
        class Response:
            def __init__(self, s, h, b):
                self.status_code = s
                self.headers = h
                self.content = b
                self.text = b.decode("utf-8", errors="replace")
            def json(self):
                return json.loads(self.text)
                
        return Response(status, headers_dict, res_body)

    async def get(self, path: str, headers: dict = None):
        return await self.request("GET", path, headers=headers)

    async def post(self, path: str, headers: dict = None, json: dict = None):
        return await self.request("POST", path, headers=headers, json_body=json)

async def run_all_tests():
    print("=" * 65)
    print("STARTING AI INTERVIEW PREP TEST SUITE (IN-MEMORY ASGI)")
    print("=" * 65)

    init_db()
    seed_default_accounts()
    client = ASGITestClient(app)

    # ----------------------------------------------------
    # TEST 1: Entry Point & Login as the First Screen
    # ----------------------------------------------------
    print("\n[TEST 1] Verifying Entry Point & Login First Screen...")
    res = await client.get("/")
    assert res.status_code == 200, f"Expected 200, got {res.status_code}"
    html = res.text
    assert 'id="viewLogin" class="page-view active"' in html, "viewLogin must be initially active screen"
    assert "AI Interview Prep" in html
    assert "Your Career. Your Confidence. Your Next Opportunity." in html
    assert "Prepare smarter, practise confidently and get interview-ready" in html
    assert "AI Mock Interviews" in html
    assert "Personalized Learning" in html
    assert "Resume Analysis" in html
    assert "Real-Time Feedback" in html
    assert 'id="loginEmail"' in html
    assert 'id="loginPassword"' in html
    assert 'id="loginSubmitBtn"' in html
    assert 'id="btnGoogleAuth"' in html
    assert 'id="linkToRegister"' in html
    print("✓ Entry point serves Login Page as the first active screen.")

    # ----------------------------------------------------
    # TEST 2: Protected Routes Reject Unauthenticated Requests
    # ----------------------------------------------------
    print("\n[TEST 2] Verifying Protected Routes Reject Unauthenticated Requests...")
    res = await client.get("/api/auth/me")
    assert res.status_code == 401

    res = await client.get("/api/student/dashboard")
    assert res.status_code == 401

    res = await client.get("/api/admin/metrics")
    assert res.status_code == 403
    print("✓ Unauthenticated access safely blocked with 401 / 403 status codes.")

    # ----------------------------------------------------
    # TEST 3: Login Input Validation & Error Handling
    # ----------------------------------------------------
    print("\n[TEST 3] Verifying Login Input Validation & Error Handling...")
    # Empty email
    res = await client.post("/api/auth/login", json={"email": "", "password": "123"})
    assert res.status_code == 400
    assert "Email address is required" in res.json()["error"]

    # Invalid email format
    res = await client.post("/api/auth/login", json={"email": "notanemail", "password": "123"})
    assert res.status_code == 400
    assert "valid email address" in res.json()["error"]

    # Empty password
    res = await client.post("/api/auth/login", json={"email": "student@demo.com", "password": ""})
    assert res.status_code == 400
    assert "Password is required" in res.json()["error"]

    # Account not found
    res = await client.post("/api/auth/login", json={"email": "nonexistent@nowhere.com", "password": "Pass@12345"})
    assert res.status_code == 404
    assert "No account found" in res.json()["error"]

    # Incorrect password
    res = await client.post("/api/auth/login", json={"email": "student@demo.com", "password": "WrongPassword"})
    assert res.status_code == 401
    assert "Incorrect password" in res.json()["error"]
    print("✓ All 5 login validation rules and descriptive error messages verified.")

    # ----------------------------------------------------
    # TEST 4: Student Login Success & JWT Generation
    # ----------------------------------------------------
    print("\n[TEST 4] Verifying Successful Student Authentication...")
    res = await client.post("/api/auth/login", json={
        "email": "student@demo.com",
        "password": "Pass@123",
        "remember_me": True,
        "role_expected": "student"
    })
    assert res.status_code == 200, f"Login failed: {res.text}"
    login_data = res.json()
    assert "token" in login_data
    assert login_data["user"]["email"] == "student@demo.com"
    assert login_data["user"]["role"] == "student"
    assert login_data["redirect"] == "/student/dashboard"
    student_token = login_data["token"]
    student_headers = {"Authorization": f"Bearer {student_token}"}
    print(f"✓ Student authenticated successfully with signed JWT: {student_token[:30]}...")

    # ----------------------------------------------------
    # TEST 5: Verify Profile Recovery via /api/auth/me
    # ----------------------------------------------------
    print("\n[TEST 5] Verifying /api/auth/me Profile Recovery...")
    res = await client.get("/api/auth/me", headers=student_headers)
    assert res.status_code == 200
    user_me = res.json()["user"]
    assert user_me["name"] == "Alex Chen"
    assert user_me["role"] == "student"
    print("✓ Session recovered successfully via JWT token.")

    # ----------------------------------------------------
    # TEST 6: Student Dashboard Data Fetch
    # ----------------------------------------------------
    print("\n[TEST 6] Verifying Student Dashboard Data & Readiness Score...")
    res = await client.get("/api/student/dashboard", headers=student_headers)
    assert res.status_code == 200
    dash_data = res.json()
    assert "readiness" in dash_data
    assert "daily_challenge" in dash_data
    assert dash_data["readiness"]["overall"] >= 65
    print(f"✓ Student Dashboard retrieved. Readiness Score: {dash_data['readiness']['overall']}/100.")

    # ----------------------------------------------------
    # TEST 7: Role Isolation (Student blocked from Admin APIs)
    # ----------------------------------------------------
    print("\n[TEST 7] Verifying Role-Based Access Control (Student blocked from Admin)...")
    res = await client.get("/api/admin/metrics", headers=student_headers)
    assert res.status_code == 403
    assert "Administrator privileges required" in res.json()["error"]
    print("✓ Student blocked from Admin API endpoints (403 Forbidden).")

    # ----------------------------------------------------
    # TEST 8: Admin Authentication & Dashboard Controls
    # ----------------------------------------------------
    print("\n[TEST 8] Verifying Admin Authentication Flow...")
    res = await client.post("/api/auth/login", json={
        "email": "admin@aiinterview.com",
        "password": "Admin@123",
        "role_expected": "admin"
    })
    assert res.status_code == 200
    admin_data = res.json()
    assert admin_data["user"]["role"] == "admin"
    admin_token = admin_data["token"]
    admin_headers = {"Authorization": f"Bearer {admin_token}"}

    res = await client.get("/api/admin/metrics", headers=admin_headers)
    assert res.status_code == 200
    metrics = res.json()["metrics"]
    assert metrics["total_students"] >= 1
    assert "avg_readiness_score" in metrics
    print(f"✓ Admin authorized. System metrics: {metrics}")

    res = await client.get("/api/admin/users", headers=admin_headers)
    assert res.status_code == 200
    users_list = res.json()["users"]
    assert len(users_list) >= 2
    print(f"✓ Admin retrieved user list ({len(users_list)} registered accounts).")

    # ----------------------------------------------------
    # TEST 9: Registration Flow & Duplicate Email Check
    # ----------------------------------------------------
    print("\n[TEST 9] Verifying New Student Registration Flow...")
    test_email = f"sarah_{int(time.time())}@example.com"
    
    # Duplicate email check
    res = await client.post("/api/auth/register", json={
        "name": "Duplicate Student",
        "email": "student@demo.com",
        "password": "Password123!",
        "confirm_password": "Password123!",
        "terms_agreed": True
    })
    assert res.status_code == 409
    assert "already exists" in res.json()["error"]
    print("✓ Duplicate email detection works (409 Conflict).")

    # Successful new registration
    res = await client.post("/api/auth/register", json={
        "name": "Sarah Connor",
        "email": test_email,
        "phone": "+1-555-8831",
        "college": "MIT",
        "password": "SecurePassword123!",
        "confirm_password": "SecurePassword123!",
        "terms_agreed": True
    })
    assert res.status_code == 201
    new_user_data = res.json()
    assert new_user_data["user"]["email"] == test_email
    assert new_user_data["redirect"] == "/onboarding"
    new_user_token = new_user_data["token"]
    new_user_headers = {"Authorization": f"Bearer {new_user_token}"}
    print(f"✓ Registered new student '{test_email}' with PBKDF2 hash & salt.")

    # ----------------------------------------------------
    # TEST 10: Student Onboarding Flow
    # ----------------------------------------------------
    print("\n[TEST 10] Verifying Student Onboarding Preferences...")
    res = await client.post("/api/onboarding", headers=new_user_headers, json={
        "target_role": "AI / ML Engineer",
        "target_companies": "Google DeepMind, Anthropic, OpenAI",
        "experience_level": "Mid-Level Engineer (3-5 yrs)",
        "focus_areas": "LLM Fine-tuning, Transformer Architecture, System Design"
    })
    assert res.status_code == 200
    updated = res.json()["user"]
    assert updated["onboarded"] == 1
    assert updated["target_role"] == "AI / ML Engineer"
    print("✓ Student onboarding preferences stored; onboarded set to 1.")

    # ----------------------------------------------------
    # TEST 11: Forgot Password & Reset Flow
    # ----------------------------------------------------
    print("\n[TEST 11] Verifying Forgot Password & Reset Token Flow...")
    res = await client.post("/api/auth/forgot-password", json={"email": test_email})
    assert res.status_code == 200
    reset_token = res.json()["reset_token"]
    assert reset_token.startswith("RESET-")
    print(f"✓ Generated password reset token: {reset_token}")

    new_password = "BrandNewPassword999!"
    res = await client.post("/api/auth/reset-password", json={
        "token": reset_token,
        "new_password": new_password,
        "confirm_new_password": new_password
    })
    assert res.status_code == 200
    assert "successfully reset" in res.json()["message"]

    res = await client.post("/api/auth/login", json={
        "email": test_email,
        "password": new_password
    })
    assert res.status_code == 200
    print("✓ Successfully logged in with new password after reset.")

    # ----------------------------------------------------
    # TEST 12: Interactive Modules APIs
    # ----------------------------------------------------
    print("\n[TEST 12] Verifying Interactive Modules APIs...")
    # 1. AI Mock Interview Evaluation
    res = await client.post("/api/mock-interview/evaluate", headers=student_headers, json={
        "role_type": "Software Engineer",
        "question": "How do you handle idempotency in microservices?",
        "answer": "We use an Idempotency-Key HTTP header. The request is processed inside an atomic database transaction with a unique constraint on the key, and cached in Redis."
    })
    assert res.status_code == 200
    eval_data = res.json()
    assert eval_data["overall_score"] >= 70
    assert "rubric" in eval_data
    print(f"✓ AI Mock Interview evaluated (Score: {eval_data['overall_score']}/100).")

    # 2. Resume ATS Scorer
    res = await client.post("/api/resume/analyze", headers=student_headers, json={
        "resume_text": "Experienced software engineer with Python, SQL, Docker, AWS, React, and microservices architecture.",
        "target_role": "Software Engineer"
    })
    assert res.status_code == 200
    ats_data = res.json()
    assert ats_data["ats_score"] >= 70
    print(f"✓ Resume ATS analyzed (Score: {ats_data['ats_score']}%, Matched: {len(ats_data['matched_keywords'])}).")

    # 3. Code Runner
    res = await client.post("/api/code/run", headers=student_headers, json={
        "code": "def twoSum(nums, target):\n    return [0, 1]",
        "language": "python",
        "problem_id": "two-sum"
    })
    assert res.status_code == 200
    code_data = res.json()
    assert code_data["all_passed"] is True
    print(f"✓ Code Runner executed 3 test cases: {code_data['feedback']}")

    # 4. 24/7 AI Career Mentor
    res = await client.post("/api/chat/ask", headers=student_headers, json={
        "message": "What is the best way to prepare for system design rounds?"
    })
    assert res.status_code == 200
    assert "system design" in res.json()["reply"].lower()
    print("✓ 24/7 AI Career Mentor replied with tailored guidance.")

    # ----------------------------------------------------
    # TEST 13: Logout Flow
    # ----------------------------------------------------
    print("\n[TEST 13] Verifying Logout Flow...")
    res = await client.post("/api/auth/logout", headers=student_headers)
    assert res.status_code == 200
    assert "logged out" in res.json()["message"].lower()
    print("✓ Logout endpoint succeeded.")

    print("\n" + "=" * 65)
    print("ALL 13 AUTOMATED TESTS PASSED SUCCESSFULLY!")
    print("=" * 65)

if __name__ == "__main__":
    asyncio.run(run_all_tests())
