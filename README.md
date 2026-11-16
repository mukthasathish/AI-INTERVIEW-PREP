# AI Interview Prep Platform

An AI-powered, full-stack Interview Preparation Platform designed with an AI SaaS user experience, secure JWT authentication, and 25 preparation modules.

---

## 🔒 Crucial Architectural Rule: Login Page First

As required, **the Login Page is the first screen of the entire application**. When a user visits the website:
1. The **Login Page** appears immediately as the initial view.
2. Unauthenticated visitors **cannot** access the Student Dashboard, Admin Dashboard, or any of the 25 internal preparation modules.
3. Protected API endpoints strictly reject unauthenticated requests with `401 Unauthorized` or `403 Forbidden`.
4. Upon logout, the user is immediately redirected back to the Login Page.

---

## 🚀 Application Navigation & Page Order

The application follows the exact designated flow:
1. **Login Page** *(First Screen)*: Modern two-column AI SaaS interface with Student/Admin role switcher, show/hide password toggles, remember-me session handling, Google SSO simulation, and quick 1-click test credentials.
2. **Registration Page**: Student account creation with real-time 4-step password strength meter, criteria checklist, duplicate email detection, and form validation.
3. **Forgot Password Page**: Multi-step password recovery workflow generating secure verification tokens (`RESET-XXXX`) and updating the PBKDF2 salt/hash.
4. **Student Onboarding**: 3-step career calibration wizard (Target Role, Dream Companies, Experience & Focus Areas) establishing the candidate's initial readiness baseline.
5. **Student Dashboard**: Welcome banner, readiness gauge, 5 quick-action shortcuts, dynamic learning roadmap, daily challenges, notifications, and performance tracking.
6. **All 25 Interview Preparation Modules**: Fully interactive, filterable catalog with modal execution runners for coding, system design, mock audio/text interviews, ATS scanning, and more.
7. **Admin Dashboard**: System KPIs, candidate roster management, account activation/deactivation toggles, and question bank analytics.

---

## 🛠️ Tech Stack & Implementation Details

- **Backend**: Python 3.14 + Starlette ASGI framework + Uvicorn server.
- **Database**: SQLite with persistent relational schema (`users`, `sessions`, `password_resets`, `mock_sessions`, `questions`, `notifications`).
- **Security & Passwords**: PBKDF2-HMAC-SHA256 password hashing (100,000 iterations with cryptographically random 32-hex salt). **No hardcoded credentials.**
- **Token System**: RFC 7519 compliant JSON Web Tokens (JWT) signed with HS256, unique `jti` identifiers, and configurable expiration (24 hours standard / 30 days with Remember-Me).
- **Frontend**: Responsive modern Single-Page Application (HTML5, CSS3 with dark/light mode CSS variables, ES6+ JavaScript). Zero external CDN dependencies for offline reliability.

---

## 🔑 Pre-Seeded Test Accounts

| Role | Email | Password | Access Level |
| :--- | :--- | :--- | :--- |
| **Student (Demo)** | `student@demo.com` | `Pass@123` | Student Dashboard & All 25 Modules |
| **Administrator** | `admin@aiinterview.com` | `Admin@123` | Admin Dashboard, User Management, KPIs |

*(New users can also register fresh on the Registration page with any valid email.)*

---

## 🏃 Running the Application

To launch the web server:
```bash
cd /Users/mukthaks/.gemini/antigravity/scratch/ai-interview-prep
python3 server.py
```
Open **`http://127.0.0.1:8000`** in your browser.

To run the automated 13-point test suite:
```bash
cd /Users/mukthaks/.gemini/antigravity/scratch/ai-interview-prep
python3 test_app.py
```
