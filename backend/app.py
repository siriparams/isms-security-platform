from flask import Flask, request, jsonify
from flask_cors import CORS
import psycopg2
from psycopg2.extras import Json
import os
import jwt
import datetime
from functools import wraps
from dotenv import load_dotenv

# =========================================================
# LOAD ENVIRONMENT VARIABLES
# =========================================================

load_dotenv()

DB_HOST = os.getenv("DB_HOST", "localhost")
DB_NAME = os.getenv("DB_NAME", "isms_db")
DB_USER = os.getenv("DB_USER", "postgres")
DB_PASSWORD = os.getenv("DB_PASSWORD", "")
DB_PORT = os.getenv("DB_PORT", "5432")

JWT_SECRET_KEY = os.getenv(
    "JWT_SECRET_KEY",
    "change_this_jwt_secret"
)

AGENT_API_KEY = os.getenv(
    "AGENT_API_KEY",
    "isms_agent_2026_secure_key"
)

ADMIN_USERNAME = os.getenv(
    "ADMIN_USERNAME",
    "admin"
)

ADMIN_PASSWORD = os.getenv(
    "ADMIN_PASSWORD",
    "admin123"
)

# =========================================================
# FLASK APPLICATION
# =========================================================

app = Flask(__name__)

CORS(
    app,
    resources={
        r"/*": {
            "origins": "*"
        }
    }
)

# =========================================================
# DATABASE CONNECTION
# =========================================================

def get_db_connection():

    return psycopg2.connect(
        host=DB_HOST,
        database=DB_NAME,
        user=DB_USER,
        password=DB_PASSWORD,
        port=DB_PORT
    )


# =========================================================
# INITIALIZE DATABASE
# =========================================================

def initialize_database():

    try:

        conn = get_db_connection()
        cur = conn.cursor()

        # -------------------------------------------------
        # USERS TABLE
        # -------------------------------------------------

        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(100) UNIQUE NOT NULL,
                password VARCHAR(255) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # -------------------------------------------------
        # ASSETS TABLE
        # -------------------------------------------------

        cur.execute("""
            CREATE TABLE IF NOT EXISTS assets (
                id SERIAL PRIMARY KEY,

                hostname TEXT,

                ip_address TEXT,

                operating_system JSONB,

                hardware JSONB,

                network JSONB,

                software JSONB,

                management JSONB,

                security_posture JSONB,

                user_context JSONB,

                device_identity JSONB,

                host_identity JSONB,

                discovery_timestamp TIMESTAMP,

                platform TEXT,

                agent_version TEXT,

                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Existing databases may already have the assets table without
        # created_at. Ensure the column exists before /assets is queried.
        cur.execute("""
            ALTER TABLE assets
            ADD COLUMN IF NOT EXISTS created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        """)

        # -------------------------------------------------
        # CREATE ADMIN USER IF NOT PRESENT
        # -------------------------------------------------

        cur.execute(
            """
            SELECT id
            FROM users
            WHERE username = %s
            """,
            (ADMIN_USERNAME,)
        )

        existing_user = cur.fetchone()

        if not existing_user:

            cur.execute(
                """
                INSERT INTO users
                (
                    username,
                    password
                )
                VALUES
                (
                    %s,
                    %s
                )
                """,
                (
                    ADMIN_USERNAME,
                    ADMIN_PASSWORD
                )
            )

        conn.commit()

        cur.close()
        conn.close()

        print("PostgreSQL connected successfully!")

    except Exception as e:

        print("Database initialization error:")
        print(e)


# =========================================================
# JWT TOKEN CREATION
# =========================================================

def create_token(username):

    payload = {
        "username": username,
        "exp": datetime.datetime.now(
            datetime.timezone.utc
        ) + datetime.timedelta(hours=8)
    }

    token = jwt.encode(
        payload,
        JWT_SECRET_KEY,
        algorithm="HS256"
    )

    return token


# =========================================================
# JWT AUTHENTICATION DECORATOR
# =========================================================

def token_required(function):

    @wraps(function)
    def decorated(*args, **kwargs):

        auth_header = request.headers.get(
            "Authorization"
        )

        if not auth_header:

            return jsonify({
                "success": False,
                "message": "Authorization token is missing"
            }), 401

        try:

            parts = auth_header.split(" ")

            if len(parts) != 2:

                raise Exception(
                    "Invalid authorization format"
                )

            token = parts[1]

            decoded = jwt.decode(
                token,
                JWT_SECRET_KEY,
                algorithms=["HS256"]
            )

            request.current_user = decoded[
                "username"
            ]

        except jwt.ExpiredSignatureError:

            return jsonify({
                "success": False,
                "message": "Token has expired"
            }), 401

        except Exception:

            return jsonify({
                "success": False,
                "message": "Invalid token"
            }), 401

        return function(*args, **kwargs)

    return decorated


# =========================================================
# HOME
# =========================================================

@app.route("/", methods=["GET"])
def home():

    return "ISMS Backend is running!"


# =========================================================
# LOGIN
# =========================================================

@app.route("/login", methods=["POST"])
def login():

    try:

        data = request.get_json()

        if not data:

            return jsonify({
                "success": False,
                "message": "JSON data is missing"
            }), 400

        username = data.get("username")
        password = data.get("password")

        if not username or not password:

            return jsonify({
                "success": False,
                "message": "Username and password are required"
            }), 400

        conn = get_db_connection()
        cur = conn.cursor()

        cur.execute(
            """
            SELECT id, username, password
            FROM users
            WHERE username = %s
            """,
            (username,)
        )

        user = cur.fetchone()

        cur.close()
        conn.close()

        if not user:

            return jsonify({
                "success": False,
                "message": "Invalid username or password"
            }), 401

        user_id = user[0]
        db_username = user[1]
        db_password = user[2]

        if password != db_password:

            return jsonify({
                "success": False,
                "message": "Invalid username or password"
            }), 401

        token = create_token(
            db_username
        )

        return jsonify({
            "success": True,
            "message": "Login successful",
            "token": token,
            "user": {
                "id": user_id,
                "username": db_username
            }
        }), 200

    except Exception as e:

        print("Login error:", e)

        return jsonify({
            "success": False,
            "message": "Login failed",
            "error": str(e)
        }), 500


# =========================================================
# RECEIVE ASSET FROM WINDOWS AGENT
# =========================================================

@app.route(
    "/agent/assets",
    methods=["POST"]
)
def receive_agent_asset():

    try:

        # -------------------------------------------------
        # CHECK AGENT API KEY
        # -------------------------------------------------

        api_key = request.headers.get(
            "X-Agent-API-Key"
        )

        if not api_key:

            return jsonify({
                "success": False,
                "message": "Agent API key is missing"
            }), 401

        if api_key != AGENT_API_KEY:

            return jsonify({
                "success": False,
                "message": "Invalid agent API key"
            }), 401

        # -------------------------------------------------
        # READ JSON
        # -------------------------------------------------

        data = request.get_json(
            force=True,
            silent=False
        )

        if not data:

            return jsonify({
                "success": False,
                "message": "JSON data is missing"
            }), 400

        print("")
        print("============================================")
        print("Asset received from agent")
        print("============================================")

        # -------------------------------------------------
        # EXTRACT DATA
        # -------------------------------------------------

        device_identity = data.get(
            "device_identity",
            {}
        )

        host_identity = data.get(
            "host_identity",
            {}
        )

        hardware = data.get(
            "hardware",
            {}
        )

        network = data.get(
            "network",
            []
        )

        os_info = data.get(
            "os",
            {}
        )

        management = data.get(
            "management",
            []
        )

        security = data.get(
            "security_posture",
            {}
        )

        software = data.get(
            "software",
            []
        )

        user_context = data.get(
            "user_context",
            {}
        )

        # -------------------------------------------------
        # IMPORTANT:
        # IP ADDRESS IS NOT STORED
        # -------------------------------------------------

        ip_address = None

        # -------------------------------------------------
        # DATABASE
        # -------------------------------------------------

        conn = get_db_connection()
        cur = conn.cursor()

        cur.execute(
            """
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
                user_context,
                device_identity,
                host_identity,
                discovery_timestamp,
                platform,
                agent_version
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
                %s,
                %s,
                %s,
                %s,
                %s,
                %s
            )
            RETURNING id
            """,
            (
                host_identity.get("Hostname"),

                ip_address,

                Json(os_info),

                Json(hardware),

                Json(network),

                Json(software),

                Json(management),

                Json(security),

                Json(user_context),

                Json(device_identity),

                Json(host_identity),

                data.get(
                    "discovery_timestamp"
                ),

                data.get(
                    "platform"
                ),

                data.get(
                    "agent_version",
                    "1.0.0"
                )
            )
        )

        asset_id = cur.fetchone()[0]

        conn.commit()

        cur.close()
        conn.close()

        print(
            f"Asset stored successfully. ID: {asset_id}"
        )

        return jsonify({
            "success": True,
            "message": "Agent asset received successfully",
            "asset_id": asset_id
        }), 201

    except Exception as e:

        print(
            "Agent upload error:",
            str(e)
        )

        return jsonify({
            "success": False,
            "message": "Failed to process agent asset",
            "error": str(e)
        }), 500


# =========================================================
# GET ASSETS FOR ANGULAR FRONTEND
# =========================================================

@app.route(
    "/assets",
    methods=["GET"]
)
@token_required
def get_assets():

    try:

        conn = get_db_connection()
        cur = conn.cursor()

        cur.execute(
            """
            SELECT
                id,
                hostname,
                operating_system,
                hardware,
                network,
                software,
                management,
                security_posture,
                user_context,
                device_identity,
                host_identity,
                discovery_timestamp,
                platform,
                agent_version,
                created_at
            FROM assets
            ORDER BY id DESC
            """
        )

        rows = cur.fetchall()

        assets = []

        for row in rows:

            assets.append({

                "id": row[0],

                "hostname": row[1],

                "operating_system": row[2],

                "hardware": row[3],

                "network": row[4],

                "software": row[5],

                "management": row[6],

                "security_posture": row[7],

                "user_context": row[8],

                "device_identity": row[9],

                "host_identity": row[10],

                "discovery_timestamp": (
                    row[11].isoformat()
                    if row[11]
                    else None
                ),

                "platform": row[12],

                "agent_version": row[13],

                "created_at": (
                    row[14].isoformat()
                    if row[14]
                    else None
                )
            })

        cur.close()
        conn.close()

        return jsonify(assets), 200

    except Exception as e:

        print(
            "Get assets error:",
            e
        )

        return jsonify({
            "success": False,
            "message": "Failed to retrieve assets",
            "error": str(e)
        }), 500


# =========================================================
# LOGOUT
# =========================================================

@app.route(
    "/logout",
    methods=["POST"]
)
@token_required
def logout():

    return jsonify({
        "success": True,
        "message": "Logout successful"
    }), 200


# =========================================================
# START FLASK SERVER
# =========================================================

if __name__ == "__main__":

    initialize_database()

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )