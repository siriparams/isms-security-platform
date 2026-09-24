from flask import Flask, request, jsonify
from flask_cors import CORS
import psycopg2
from psycopg2.extras import Json
import os
import jwt
import datetime
import subprocess
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

        cur.execute("""
            ALTER TABLE assets
            ADD COLUMN IF NOT EXISTS machine_guid TEXT,
            ADD COLUMN IF NOT EXISTS smbios_uuid TEXT,
            ADD COLUMN IF NOT EXISTS agent_enabled BOOLEAN DEFAULT TRUE,
            ADD COLUMN IF NOT EXISTS last_check_in TIMESTAMP WITH TIME ZONE,
            ADD COLUMN IF NOT EXISTS heartbeat_interval_seconds INTEGER DEFAULT 300,
            ADD COLUMN IF NOT EXISTS last_used TIMESTAMP WITH TIME ZONE,
            ADD COLUMN IF NOT EXISTS last_status_change TIMESTAMP WITH TIME ZONE,
            ADD COLUMN IF NOT EXISTS online_status TEXT DEFAULT 'UNKNOWN',
            ADD COLUMN IF NOT EXISTS alert_status TEXT DEFAULT 'NONE',
            ADD COLUMN IF NOT EXISTS device_last_seen TIMESTAMP WITH TIME ZONE
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

        api_key = request.headers.get("X-Agent-API-Key")

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

        data = request.get_json(force=True, silent=False)

        if not data:
            return jsonify({
                "success": False,
                "message": "JSON data is missing"
            }), 400

        device_identity = data.get("device_identity", {})
        host_identity = data.get("host_identity", {})
        hardware = data.get("hardware", {})
        network = data.get("network", [])
        os_info = data.get("os", {})
        management = data.get("management", [])
        security = data.get("security_posture", {})
        software = data.get("software", [])
        user_context = data.get("user_context", {})

        machine_guid = device_identity.get("Machine_GUID")
        smbios_uuid = device_identity.get("SMBIOS_UUID")

        if not machine_guid or not smbios_uuid:
            return jsonify({
                "success": False,
                "message": "Machine GUID and SMBIOS UUID are required"
            }), 400

        conn = get_db_connection()
        cur = conn.cursor()

        # Same machine = same GUID + SMBIOS UUID.
        # Update the existing asset instead of creating a duplicate.
        cur.execute(
            """
            SELECT id
            FROM assets
            WHERE machine_guid = %s
              AND smbios_uuid = %s
            LIMIT 1
            """,
            (machine_guid, smbios_uuid)
        )

        existing = cur.fetchone()

        if existing:
            asset_id = existing[0]

            cur.execute(
                """
                UPDATE assets
                SET
                    hostname = %s,
                    operating_system = %s,
                    hardware = %s,
                    network = %s,
                    software = %s,
                    management = %s,
                    security_posture = %s,
                    user_context = %s,
                    device_identity = %s,
                    host_identity = %s,
                    discovery_timestamp = %s,
                    platform = %s,
                    agent_version = %s
                WHERE id = %s
                """,
                (
                    host_identity.get("Hostname"),
                    Json(os_info),
                    Json(hardware),
                    Json(network),
                    Json(software),
                    Json(management),
                    Json(security),
                    Json(user_context),
                    Json(device_identity),
                    Json(host_identity),
                    data.get("discovery_timestamp"),
                    data.get("platform"),
                    data.get("agent_version", "1.0.0"),
                    asset_id
                )
            )

            action = "updated"

        else:
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
                    agent_version,
                    machine_guid,
                    smbios_uuid,
                    agent_enabled,
                    last_check_in,
                    heartbeat_interval_seconds,
                    last_status_change,
                    online_status,
                    alert_status
                )
                VALUES
                (
                    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                    %s, %s, %s, %s, TRUE, NOW(), 300, NOW(), 'ONLINE', 'NONE'
                )
                RETURNING id
                """,
                (
                    host_identity.get("Hostname"),
                    None,
                    Json(os_info),
                    Json(hardware),
                    Json(network),
                    Json(software),
                    Json(management),
                    Json(security),
                    Json(user_context),
                    Json(device_identity),
                    Json(host_identity),
                    data.get("discovery_timestamp"),
                    data.get("platform"),
                    data.get("agent_version", "1.0.0"),
                    machine_guid,
                    smbios_uuid
                )
            )

            asset_id = cur.fetchone()[0]
            action = "created"

        conn.commit()
        cur.close()
        conn.close()

        return jsonify({
            "success": True,
            "message": f"Agent asset {action} successfully",
            "asset_id": asset_id,
            "action": action
        }), 201

    except Exception as e:

        print("Agent upload error:", str(e))

        return jsonify({
            "success": False,
            "message": "Failed to process agent asset",
            "error": str(e)
        }), 500


# =========================================================
# RECEIVE AGENT HEARTBEAT
# =========================================================

@app.route(
    "/agent/heartbeat",
    methods=["POST"]
)
def receive_agent_heartbeat():

    try:

        api_key = request.headers.get("X-Agent-API-Key")

        if api_key != AGENT_API_KEY:
            return jsonify({
                "success": False,
                "message": "Invalid agent API key"
            }), 401

        data = request.get_json(force=True, silent=False)

        machine_guid = data.get("machine_guid")
        smbios_uuid = data.get("smbios_uuid")
        agent_version = data.get("agent_version", "1.0.0")
        last_used_value = data.get("last_used")

        if not machine_guid or not smbios_uuid:
            return jsonify({
                "success": False,
                "message": "Machine GUID and SMBIOS UUID are required"
            }), 400

        conn = get_db_connection()
        cur = conn.cursor()

        cur.execute(
            """
            UPDATE assets
            SET
                agent_enabled = TRUE,
                last_check_in = NOW(),
                heartbeat_interval_seconds = 300,
                last_used = %s,
                online_status = 'ONLINE',
                alert_status = 'NONE',
                last_status_change = CASE
                    WHEN online_status <> 'ONLINE'
                         OR online_status IS NULL
                    THEN NOW()
                    ELSE last_status_change
                END,
                agent_version = %s
            WHERE machine_guid = %s
              AND smbios_uuid = %s
            RETURNING id
            """,
            (last_used_value, agent_version, machine_guid, smbios_uuid)
        )

        result = cur.fetchone()

        if not result:
            conn.rollback()
            cur.close()
            conn.close()

            return jsonify({
                "success": False,
                "message": "Asset not registered. Run asset discovery first."
            }), 404

        asset_id = result[0]

        conn.commit()
        cur.close()
        conn.close()

        return jsonify({
            "success": True,
            "message": "Heartbeat received",
            "asset_id": asset_id,
            "online_status": "ONLINE"
        }), 200

    except Exception as e:

        print("Heartbeat error:", str(e))

        return jsonify({
            "success": False,
            "message": "Failed to process heartbeat",
            "error": str(e)
        }), 500


# =========================================================
# DEVICE REACHABILITY
# =========================================================

def check_device_reachable(hostname):
    """
    Simple independent device reachability check.

    This is separate from the agent heartbeat:
    - heartbeat tells us whether the agent is responding
    - ping tells us whether the device itself is reachable on the network

    This is useful for distinguishing:
    DEVICE REACHABLE + AGENT NOT RESPONDING
    from:
    DEVICE NOT REACHABLE
    """
    if not hostname:
        return False

    try:
        result = subprocess.run(
            ["ping", "-n", "1", "-w", "1000", str(hostname)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=2
        )
        return result.returncode == 0
    except Exception:
        return False


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
                created_at,
                machine_guid,
                smbios_uuid,
                agent_enabled,
                last_check_in,
                heartbeat_interval_seconds,
                last_used,
                last_status_change,
                online_status,
                alert_status,
                device_last_seen
            FROM assets
            ORDER BY id DESC
            """
        )

        rows = cur.fetchall()
        assets = []

        for row in rows:

            (
                asset_id,
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
                created_at,
                machine_guid,
                smbios_uuid,
                agent_enabled,
                last_check_in,
                heartbeat_interval_seconds,
                last_used,
                last_status_change,
                online_status,
                alert_status,
                device_last_seen
            ) = row

            status = online_status or "UNKNOWN"
            alert = alert_status or "NONE"

            # Independent device reachability check.
            # This does NOT use the heartbeat.
            device_reachable = check_device_reachable(hostname)

            if device_reachable:
                device_last_seen = datetime.datetime.now(
                    datetime.timezone.utc
                )

                cur.execute(
                    """
                    UPDATE assets
                    SET device_last_seen = %s
                    WHERE id = %s
                    """,
                    (device_last_seen, asset_id)
                )

            if agent_enabled is False:
                status = "AGENT_DISABLED"
                alert = "AGENT_DISABLED"

            elif last_check_in is None:
                if device_reachable:
                    status = "AGENT_NOT_RESPONDING"
                    alert = "AGENT_NOT_RESPONDING"
                else:
                    status = "OFFLINE"
                    alert = "DEVICE_OFFLINE"

            else:
                allowed_seconds = (heartbeat_interval_seconds or 300) * 2
                age_seconds = (
                    datetime.datetime.now(datetime.timezone.utc)
                    - last_check_in
                ).total_seconds()

                if age_seconds <= allowed_seconds:
                    status = "ONLINE"
                    alert = "NONE"

                elif device_reachable:
                    status = "AGENT_NOT_RESPONDING"
                    alert = "AGENT_NOT_RESPONDING"

                else:
                    status = "OFFLINE"
                    alert = "DEVICE_OFFLINE"

            assets.append({
                "id": asset_id,
                "hostname": hostname,
                "operating_system": operating_system,
                "hardware": hardware,
                "network": network,
                "software": software,
                "management": management,
                "security_posture": security_posture,
                "user_context": user_context,
                "device_identity": device_identity,
                "host_identity": host_identity,
                "discovery_timestamp": (
                    discovery_timestamp.isoformat()
                    if discovery_timestamp else None
                ),
                "platform": platform,
                "agent_version": agent_version,
                "created_at": (
                    created_at.isoformat()
                    if created_at else None
                ),
                "machine_guid": machine_guid,
                "smbios_uuid": smbios_uuid,
                "agent_enabled": agent_enabled,
                "last_check_in": (
                    last_check_in.isoformat()
                    if last_check_in else None
                ),
                "heartbeat_interval_seconds":
                    heartbeat_interval_seconds,
                "last_used": (
                    last_used.isoformat()
                    if last_used else None
                ),
                "last_status_change": (
                    last_status_change.isoformat()
                    if last_status_change else None
                ),
                "online_status": status,
                "alert_status": alert,
                "device_reachable": device_reachable,
                "device_last_seen": (
                    device_last_seen.isoformat()
                    if device_last_seen else None
                )
            })

        cur.close()
        conn.close()

        return jsonify(assets), 200

    except Exception as e:

        print("Get assets error:", e)

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