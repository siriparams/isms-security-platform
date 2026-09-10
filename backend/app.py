from flask import Flask, request, jsonify
from flask_cors import CORS
import psycopg2
import os
from dotenv import load_dotenv
import jwt
from datetime import datetime, timedelta, timezone
from functools import wraps


# =========================================================
# LOAD ENVIRONMENT VARIABLES
# =========================================================

load_dotenv()


# =========================================================
# FLASK APPLICATION
# =========================================================

app = Flask(__name__)

CORS(app)


# =========================================================
# JWT CONFIGURATION
# =========================================================

JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY")

if not JWT_SECRET_KEY:
    raise RuntimeError("JWT_SECRET_KEY is missing from .env")


# =========================================================
# POSTGRESQL DATABASE CONNECTION
# =========================================================

def get_db_connection():
    return psycopg2.connect(
        host=os.getenv("DB_HOST"),
        database=os.getenv("DB_NAME"),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASSWORD"),
        port=os.getenv("DB_PORT")
    )


# =========================================================
# TEST DATABASE CONNECTION
# =========================================================

try:
    conn = get_db_connection()

    print("PostgreSQL connected successfully!")

    conn.close()

except Exception as e:

    print("PostgreSQL connection failed:", e)


# =========================================================
# JWT AUTHENTICATION DECORATOR
# =========================================================

def token_required(f):

    @wraps(f)
    def decorated(*args, **kwargs):

        auth_header = request.headers.get("Authorization")

        # No Authorization header
        if not auth_header:

            return jsonify({
                "success": False,
                "message": "JWT token is missing"
            }), 401

        try:

            # Expected format:
            # Authorization: Bearer <token>

            parts = auth_header.split()

            if len(parts) != 2 or parts[0].lower() != "bearer":

                return jsonify({
                    "success": False,
                    "message": "Invalid Authorization header"
                }), 401

            token = parts[1]

            # Decode and verify JWT
            decoded = jwt.decode(
                token,
                JWT_SECRET_KEY,
                algorithms=["HS256"]
            )

            # Store logged-in username
            request.current_user = decoded.get("username")

        except jwt.ExpiredSignatureError:

            return jsonify({
                "success": False,
                "message": "JWT token has expired"
            }), 401

        except jwt.InvalidTokenError:

            return jsonify({
                "success": False,
                "message": "Invalid JWT token"
            }), 401

        return f(*args, **kwargs)

    return decorated


# =========================================================
# LOGIN API
# =========================================================

@app.route("/login", methods=["POST"])
def login():

    data = request.get_json()

    if not data:

        return jsonify({
            "success": False,
            "message": "Request body is missing"
        }), 400

    username = data.get("username")
    password = data.get("password")

    # Current project credentials
    if username == "admin" and password == "admin123":

        # JWT payload
        payload = {
            "username": username,
            "iat": datetime.now(timezone.utc),
            "exp": datetime.now(timezone.utc) + timedelta(hours=1)
        }

        # Generate JWT token
        token = jwt.encode(
            payload,
            JWT_SECRET_KEY,
            algorithm="HS256"
        )

        return jsonify({
            "success": True,
            "message": "Login successful",
            "token": token
        }), 200

    # Invalid credentials
    return jsonify({
        "success": False,
        "message": "Invalid username or password"
    }), 401


# =========================================================
# HOME ROUTE
# =========================================================

@app.route("/", methods=["GET"])
def home():

    return "ISMS Backend is running!"


# =========================================================
# ADD ASSET
# =========================================================

@app.route("/assets", methods=["POST"])
@token_required
def add_asset():

    conn = None
    cur = None

    try:

        data = request.get_json()

        if not data:

            return jsonify({
                "success": False,
                "message": "Request body is missing"
            }), 400

        conn = get_db_connection()
        cur = conn.cursor()

        cur.execute("""
            INSERT INTO assets
            (
                hostname,
                ip_address,
                operating_system,
                hardware,
                network,
                software,
                management,
                security_posture,
                user_context
            )
            VALUES
            (
                %s,
                %s,
                %s,
                %s,
                %s,
                %s,
                %s,
                %s,
                %s
            )
            RETURNING id
        """, (
            data.get("hostname"),
            data.get("ip_address"),
            data.get("operating_system"),
            data.get("hardware"),
            data.get("network"),
            data.get("software"),
            data.get("management"),
            data.get("security_posture"),
            data.get("user_context")
        ))

        asset_id = cur.fetchone()[0]

        conn.commit()

        return jsonify({
            "success": True,
            "message": "Asset added successfully",
            "asset_id": asset_id
        }), 201

    except Exception as e:

        if conn:
            conn.rollback()

        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

    finally:

        if cur:
            cur.close()

        if conn:
            conn.close()


# =========================================================
# GET ALL ASSETS
# =========================================================

@app.route("/assets", methods=["GET"])
@token_required
def get_assets():

    conn = None
    cur = None

    try:

        conn = get_db_connection()
        cur = conn.cursor()

        cur.execute("""
            SELECT
                id,
                hostname,
                ip_address,
                operating_system,
                hardware,
                network,
                software,
                management,
                security_posture,
                user_context
            FROM assets
            ORDER BY id
        """)

        rows = cur.fetchall()

        assets = []

        for row in rows:

            assets.append({
                "id": row[0],
                "hostname": row[1],
                "ip_address": row[2],
                "operating_system": row[3],
                "hardware": row[4],
                "network": row[5],
                "software": row[6],
                "management": row[7],
                "security_posture": row[8],
                "user_context": row[9]
            })

        return jsonify(assets), 200

    except Exception as e:

        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

    finally:

        if cur:
            cur.close()

        if conn:
            conn.close()


# =========================================================
# START FLASK SERVER
# =========================================================

if __name__ == "__main__":

    app.run(
        debug=True,
        host="127.0.0.1",
        port=5000
    )