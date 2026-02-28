from __future__ import annotations

from typing import Optional, Tuple, Union
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, Response
from flask.typing import ResponseReturnValue
import firebase_admin
from firebase_admin import credentials, firestore, auth
from firebase_admin.firestore import DocumentReference
import os
from functools import wraps
import re
import requests

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("FLASK_SECRET_KEY", "dev-secret-key")

try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass

WEB_API_KEY = os.environ.get("FIREBASE_WEB_API_KEY")

# Initialize Firestore
if not firebase_admin._apps:
    service_account_path = os.getenv("FIREBASE_SERVICE_ACCOUNT", "serviceAccountKey.json")
    cred = credentials.Certificate(service_account_path)
    firebase_admin.initialize_app(cred)
db = firestore.client()

def get_current_user():
    """Return the currently logged-in user's uid (or None) by verifying the session JWT."""
    token = session.get("id_token")
    if not token:
        return None
    try:
        decoded = auth.verify_id_token(token)
        return decoded.get("uid")
    except Exception:
        session.clear()
        return None


def get_user_or_401():
    """Return the caller uid (string) or a (json, 401) response for API routes."""
    header = request.headers.get("Authorization", "")
    if not header.startswith("Bearer "):
        return jsonify({"error": "Invalid token format"}), 401

    token = header.split(" ", 1)[1].strip()
    if not token:
        return jsonify({"error": "Invalid token format"}), 401

    try:
        decoded = auth.verify_id_token(token)
        uid = decoded.get("uid")
        if not uid:
            return jsonify({"error": "Unauthorized"}), 401
        return uid
    except Exception as e:
        return jsonify({"error": f"Unauthorized: {str(e)}"}), 401


def get_profile_doc_ref(uid: str):
    """Get the Firestore document reference for a user's profile."""
    return db.collection("profiles").document(uid)


def get_profile_data(uid: str):
    """Fetch a user's profile from Firestore, returning an empty dict if missing."""
    doc = get_profile_doc_ref(uid).get()
    return doc.to_dict() if doc.exists else {}


def validate_profile_data(first_name: str, last_name: str, student_id: str):
    """Validate that required profile fields are present and well-formed."""
    if not first_name or not last_name or not student_id:
        return "All fields are required."
    return None


def normalize_profile_data(first_name: str, last_name: str, student_id: str):
    """Normalize profile field values (strip whitespace, stringify student_id)."""
    return {
        "first_name": first_name.strip() if first_name else "",
        "last_name": last_name.strip() if last_name else "",
        "student_id": str(student_id).strip() if student_id else ""
    }


def require_json_content_type():
    """Ensure the request is JSON; returns an error response tuple if not."""
    if not request.is_json:
        return jsonify({"error": "Content-Type must be application/json"}), 415
    return None


def set_profile(username: str, profile_data: dict[str, str], *, merge: bool):
    """Persist profile data to Firestore.

    Args:
        username: Profile owner.
        profile_data: Data to write.
        merge: When True, merges into existing document (partial update).
    """
    get_profile_doc_ref(username).set(profile_data, merge=merge)

def sign_in_with_password(email: str, password: str):
    if not WEB_API_KEY:
        return None, None, "Server misconfigured: FIREBASE_WEB_API_KEY is not set."

    url = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={WEB_API_KEY}"
    payload = {"email": email, "password": password, "returnSecureToken": True}

    try:
        res = requests.post(url, json=payload, timeout=10)
    except requests.RequestException:
        return None, None, "Login failed: could not reach identity provider."

    if res.status_code == 200:
        body = res.json()
        return body.get("idToken"), body.get("localId"), None

    # show the real Firebase error
    try:
        msg = res.json().get("error", {}).get("message", "UNKNOWN")
    except Exception:
        msg = "UNKNOWN"
    return None, None, msg

# --- Web Routes ---

@app.route("/")
def home():
    """Home page. Redirects to login if no active session."""
    uid = get_current_user()
    if uid:
        display = session.get("email") or uid
        return render_template("dashboard.html", username=display)
    return redirect(url_for("login"))

@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "GET":
        return render_template("signup.html")

    # JSON signup support
    if request.is_json:
        data = request.get_json(silent=True) or {}
        email = (data.get("email") or "").strip()
        password = data.get("password") or ""
        confirm_password = data.get("confirm_password") or ""

        if password != confirm_password:
            return jsonify({"error": "Passwords do not match"}), 400

        user = auth.create_user(email=email, password=password)
        db.collection("profiles").document(user.uid).set({"email": email, "role": "user"})
        return jsonify({"message": "User created", "uid": user.uid}), 201

    # Web form signup
    email = (request.form.get("email") or "").strip()
    password = request.form.get("password") or ""
    confirm_password = request.form.get("confirm_password") or ""

    if password != confirm_password:
        return render_template("signup.html", error="Passwords do not match")

    user = auth.create_user(email=email, password=password)
    db.collection("profiles").document(user.uid).set({"email": email, "role": "user"})
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")

    # JSON login for Postman: return JWT
    if request.is_json:
        data = request.get_json(silent=True) or {}
        email = (data.get("email") or "").strip()
        password = data.get("password") or ""

        token, uid, err = sign_in_with_password(email, password)
        if err or not token:
            return jsonify({"error": err or "Invalid credentials"}), 401
        return jsonify({"token": token}), 200

    # Web form login: your template uses "username", treat it as email
    email = (request.form.get("email") or request.form.get("username") or "").strip()
    password = request.form.get("password") or ""

    token, uid, err = sign_in_with_password(email, password)
    if err or not token:
        return render_template("login.html", error="Invalid credentials. Try again.")

    session.clear()
    session["id_token"] = token
    session["uid"] = uid
    session["email"] = email
    return redirect(url_for("home"))


@app.route("/logout")
def logout():
    """Clear the session and return to login."""
    session.clear()
    return redirect(url_for("login"))


@app.route("/profile", methods=["GET", "POST"])
def profile():
    """HTML form to create/update the current user's profile."""
    current_user = get_current_user()
    if not current_user:
        return redirect(url_for("login"))

    if request.method == "GET":
        profile_data = get_profile_data(current_user)
        return render_template("profile.html", profile=profile_data, error=None)

    first_name = request.form.get("first_name", "")
    last_name = request.form.get("last_name", "")
    student_id = request.form.get("student_id", "")

    error = validate_profile_data(first_name, last_name, student_id)
    if error:
        profile_data = {"first_name": first_name, "last_name": last_name, "student_id": student_id}
        return render_template("profile.html", profile=profile_data, error=error)

    normalized = normalize_profile_data(first_name, last_name, student_id)
    set_profile(current_user, normalized, merge=False)
    return redirect(url_for("home"))


# --- API Routes ---

@app.get("/api/profile")
def api_get_profile():
    """Return the current user's profile."""
    user_or_response = get_user_or_401()
    if not isinstance(user_or_response, str):
        return user_or_response

    username = user_or_response
    profile_data = get_profile_data(username)
    return jsonify({"username": username, "profile": profile_data}), 200


@app.post("/api/profile")
def api_create_profile():
    """Create/replace the current user's profile from a JSON body."""
    user_or_response = get_user_or_401()
    if not isinstance(user_or_response, str):
        return user_or_response

    username = user_or_response
    content_error = require_json_content_type()
    if content_error:
        return content_error

    data = request.get_json(silent=True) or {}
    first_name = data.get("first_name", "")
    last_name = data.get("last_name", "")
    student_id = data.get("student_id", "")

    error = validate_profile_data(first_name, last_name, student_id)
    if error:
        return jsonify({"error": error}), 400

    normalized = normalize_profile_data(first_name, last_name, student_id)
    set_profile(username, normalized, merge=False)
    return jsonify({"message": "Profile saved successfully", "profile": normalized}), 200


@app.put("/api/profile")
def api_update_profile():
    """Task 3: Bulletproof update (whitelist + bounds + collect-all-errors)."""
    uid_or_response = get_user_or_401()
    if not isinstance(uid_or_response, str):
        return uid_or_response
    uid = uid_or_response

    content_error = require_json_content_type()
    if content_error:
        return content_error

    data = request.get_json(silent=True) or {}
    if not data:
        return jsonify({"error": "Request body cannot be empty"}), 400

    allowed = {"first_name", "last_name", "student_id"}
    errors = []

    # 1) Whitelist: reject unknown fields
    unknown = set(data.keys()) - allowed
    if unknown:
        errors.append(f"Unknown fields: {sorted(unknown)}")

    update_data = {}

    # 2) Bounds checks (and minimal type checks)
    if "first_name" in data:
        val = data.get("first_name")
        if not isinstance(val, str):
            errors.append("first_name must be a string")
        else:
            val = val.strip()
            if len(val) > 50:
                errors.append("first_name must be 50 chars or less")
            update_data["first_name"] = val

    if "last_name" in data:
        val = data.get("last_name")
        if not isinstance(val, str):
            errors.append("last_name must be a string")
        else:
            val = val.strip()
            if len(val) > 50:
                errors.append("last_name must be 50 chars or less")
            update_data["last_name"] = val

    if "student_id" in data:
        sid = data.get("student_id")
        sid_str = "" if sid is None else str(sid).strip()
        if not re.fullmatch(r"[A-Za-z0-9]{8,9}", sid_str):
            errors.append("student_id must be exactly 8 or 9 alphanumeric characters")
        else:
            update_data["student_id"] = sid_str

    if not update_data:
        errors.append("No updatable fields provided")

    # 3) Collect all errors and return once
    if errors:
        return jsonify({"errors": errors}), 400

    set_profile(uid, update_data, merge=True)
    updated_profile = get_profile_data(uid)
    return jsonify({"message": "Profile updated successfully", "profile": updated_profile}), 200



@app.delete("/api/profile")
def api_delete_profile():
    """Delete the current user's profile."""
    user_or_response = get_user_or_401()
    if not isinstance(user_or_response, str):
        return user_or_response

    username = user_or_response
    get_profile_doc_ref(username).delete()
    return jsonify({"message": "Profile deleted successfully"}), 200

def require_api_key(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        expected_key = os.environ.get("SENSOR_API_KEY")
        provided_key = request.headers.get("X-API-Key")

        if not expected_key:
            return jsonify({"error": "Server misconfigured: SENSOR_API_KEY not set"}), 500

        if not provided_key or provided_key != expected_key:
            return jsonify({"error": "Unauthorized"}), 401

        return f(*args, **kwargs)
    return decorated_function

@app.post("/api/sensor_data")
@require_api_key
def api_sensor_data():
    if not request.is_json:
        return jsonify({"error": "Content-Type must be application/json"}), 415
    data = request.get_json(silent=True) or {}
    return jsonify({"message": "Sensor data received", "data": data}), 200


if __name__ == "__main__":
    app.run(debug=True, port=5000)
