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
        # AUDITS TABLE
        # -------------------------------------------------

        cur.execute("""
            CREATE TABLE IF NOT EXISTS audits (
                id SERIAL PRIMARY KEY,
                audit_id TEXT UNIQUE NOT NULL,
                asset_id INTEGER,
                hostname TEXT,
                machine_guid TEXT,
                smbios_uuid TEXT,
                operating_system TEXT,
                os_version TEXT,
                audit_profile TEXT,
                compliance_standard TEXT,
                audit_timestamp TIMESTAMP WITH TIME ZONE,
                overall_score INTEGER,
                passed_count INTEGER,
                failed_count INTEGER,
                total_checks INTEGER,
                status TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # -------------------------------------------------
        # AUDIT CHECKS TABLE
        # -------------------------------------------------

        cur.execute("""
            CREATE TABLE IF NOT EXISTS audit_checks (
                id SERIAL PRIMARY KEY,
                audit_id TEXT NOT NULL,
                check_id TEXT,
                check_name TEXT,
                category TEXT,
                expected_value TEXT,
                observed_value TEXT,
                status TEXT,
                severity TEXT,
                evidence TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
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
# RECEIVE ENDPOINT AUDIT
# =========================================================

@app.route(
    "/agent/audit",
    methods=["POST"]
)
def receive_agent_audit():

    try:

        # -------------------------------------------------
        # CHECK AGENT API KEY
        # -------------------------------------------------

        api_key = request.headers.get("X-Agent-API-Key")

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
                "message": "Audit JSON data is missing"
            }), 400

        # -------------------------------------------------
        # GET AUDIT INFORMATION
        # -------------------------------------------------

        audit_id = data.get("audit_id")
        hostname = data.get("hostname")
        machine_guid = data.get("machine_guid")
        smbios_uuid = data.get("smbios_uuid")

        if not audit_id:
            return jsonify({
                "success": False,
                "message": "audit_id is required"
            }), 400

        if not machine_guid or not smbios_uuid:
            return jsonify({
                "success": False,
                "message": "Machine GUID and SMBIOS UUID are required"
            }), 400

        # -------------------------------------------------
        # CONNECT DATABASE
        # -------------------------------------------------

        conn = get_db_connection()
        cur = conn.cursor()

        # -------------------------------------------------
        # FIND ASSET
        # -------------------------------------------------

        cur.execute(
            """
            SELECT id
            FROM assets
            WHERE machine_guid = %s
              AND smbios_uuid = %s
            LIMIT 1
            """,
            (
                machine_guid,
                smbios_uuid
            )
        )

        asset = cur.fetchone()

        if not asset:

            conn.rollback()
            cur.close()
            conn.close()

            return jsonify({
                "success": False,
                "message": "Asset not found. Run asset discovery first."
            }), 404

        asset_id = asset[0]

        # -------------------------------------------------
        # INSERT AUDIT
        # -------------------------------------------------

        cur.execute(
            """
            INSERT INTO audits
            (
                audit_id,
                asset_id,
                hostname,
                machine_guid,
                smbios_uuid,
                operating_system,
                os_version,
                audit_profile,
                compliance_standard,
                audit_timestamp,
                overall_score,
                passed_count,
                failed_count,
                total_checks,
                status
            )
            VALUES
            (
                %s, %s, %s, %s, %s, %s, %s,
                %s, %s, %s, %s, %s, %s, %s, %s
            )
            ON CONFLICT (audit_id)
            DO UPDATE SET
                asset_id = EXCLUDED.asset_id,
                hostname = EXCLUDED.hostname,
                operating_system = EXCLUDED.operating_system,
                os_version = EXCLUDED.os_version,
                audit_profile = EXCLUDED.audit_profile,
                compliance_standard = EXCLUDED.compliance_standard,
                audit_timestamp = EXCLUDED.audit_timestamp,
                overall_score = EXCLUDED.overall_score,
                passed_count = EXCLUDED.passed_count,
                failed_count = EXCLUDED.failed_count,
                total_checks = EXCLUDED.total_checks,
                status = EXCLUDED.status
            """,
            (
                audit_id,
                asset_id,
                hostname,
                machine_guid,
                smbios_uuid,
                data.get("operating_system"),
                data.get("os_version"),
                data.get("audit_profile"),
                data.get("compliance_standard"),
                data.get("audit_timestamp"),
                data.get("overall_score"),
                data.get("passed_count"),
                data.get("failed_count"),
                data.get("total_checks"),
                data.get("status")
            )
        )

        # -------------------------------------------------
        # REMOVE OLD CHECKS FOR THIS AUDIT
        # -------------------------------------------------

        cur.execute(
            """
            DELETE FROM audit_checks
            WHERE audit_id = %s
            """,
            (audit_id,)
        )

        # -------------------------------------------------
        # INSERT AUDIT CHECKS
        # -------------------------------------------------

        checks = data.get("checks", [])

        for check in checks:

            cur.execute(
                """
                INSERT INTO audit_checks
                (
                    audit_id,
                    check_id,
                    check_name,
                    category,
                    expected_value,
                    observed_value,
                    status,
                    severity,
                    evidence
                )
                VALUES
                (
                    %s, %s, %s, %s, %s,
                    %s, %s, %s, %s
                )
                """,
                (
                    audit_id,
                    check.get("check_id"),
                    check.get("check_name"),
                    check.get("category"),
                    check.get("expected_value"),
                    check.get("observed_value"),
                    check.get("status"),
                    check.get("severity"),
                    check.get("evidence", "")
                )
            )

        # -------------------------------------------------
        # SAVE
        # -------------------------------------------------

        conn.commit()

        cur.close()
        conn.close()

        return jsonify({
            "success": True,
            "message": "Endpoint audit received successfully",
            "audit_id": audit_id,
            "asset_id": asset_id,
            "checks_received": len(checks),
            "overall_score": data.get("overall_score"),
            "status": data.get("status")
        }), 201

    except Exception as e:

        print("Audit upload error:", str(e))

        return jsonify({
            "success": False,
            "message": "Failed to process endpoint audit",
            "error": str(e)
        }), 500

# =========================================================
# GET LATEST AUDIT FOR AN ASSET
# =========================================================

@app.route(
    "/audits/<int:asset_id>",
    methods=["GET"]
)
@token_required
def get_latest_audit(asset_id):

    try:

        conn = get_db_connection()
        cur = conn.cursor()

        # -------------------------------------------------
        # GET LATEST AUDIT
        # -------------------------------------------------

        cur.execute(
            """
            SELECT
                audit_id,
                asset_id,
                hostname,
                operating_system,
                os_version,
                audit_profile,
                compliance_standard,
                audit_timestamp,
                overall_score,
                passed_count,
                failed_count,
                total_checks,
                status
            FROM audits
            WHERE asset_id = %s
            ORDER BY audit_timestamp DESC, id DESC
            LIMIT 1
            """,
            (asset_id,)
        )

        audit = cur.fetchone()

        if not audit:

            cur.close()
            conn.close()

            return jsonify({
                "success": False,
                "message": "No audit result found for this asset"
            }), 404


        (
            audit_id,
            asset_id,
            hostname,
            operating_system,
            os_version,
            audit_profile,
            compliance_standard,
            audit_timestamp,
            overall_score,
            passed_count,
            failed_count,
            total_checks,
            status
        ) = audit


        # -------------------------------------------------
        # GET AUDIT CHECKS
        # -------------------------------------------------

        cur.execute(
            """
            SELECT
                id,
                audit_id,
                check_id,
                check_name,
                category,
                expected_value,
                observed_value,
                status,
                severity,
                evidence
            FROM audit_checks
            WHERE audit_id = %s
            ORDER BY id ASC
            """,
            (audit_id,)
        )

        check_rows = cur.fetchall()


        checks = []

        for row in check_rows:

            (
                check_db_id,
                check_audit_id,
                check_id,
                check_name,
                category,
                expected_value,
                observed_value,
                check_status,
                severity,
                evidence
            ) = row

            checks.append({

                "id": check_db_id,

                "audit_id": check_audit_id,

                "check_id": check_id,

                "check_name": check_name,

                "category": category,

                "expected_value": expected_value,

                "observed_value": observed_value,

                "status": check_status,

                "severity": severity,

                "evidence": evidence

            })


        cur.close()
        conn.close()


        # -------------------------------------------------
        # RETURN RESULT
        # -------------------------------------------------

        return jsonify({

            "success": True,

            "audit_id": audit_id,

            "asset_id": asset_id,

            "hostname": hostname,

            "operating_system": operating_system,

            "os_version": os_version,

            "audit_profile": audit_profile,

            "compliance_standard": compliance_standard,

            "audit_timestamp": audit_timestamp.isoformat()
                if audit_timestamp else None,

            "overall_score": overall_score,

            "passed_count": passed_count,

            "failed_count": failed_count,

            "total_checks": total_checks,

            "status": status,

            "checks": checks

        }), 200


    except Exception as e:

        print(
            "Get audit error:",
            str(e)
        )

        return jsonify({

            "success": False,

            "message":
                "Failed to retrieve audit result",

            "error":
                str(e)

        }), 500

# =========================================================
# GET LATEST AUDIT RESULT FOR AN ASSET
# =========================================================

@app.route(
    "/audits/<int:asset_id>",
    methods=["GET"]
)
@token_required
def get_latest_audit(asset_id):

    try:

        conn = get_db_connection()
        cur = conn.cursor()

        # -------------------------------------------------
        # GET LATEST AUDIT
        # -------------------------------------------------

        cur.execute(
            """
            SELECT
                audit_id,
                asset_id,
                hostname,
                operating_system,
                os_version,
                audit_profile,
                compliance_standard,
                audit_timestamp,
                overall_score,
                passed_count,
                failed_count,
                total_checks,
                status
            FROM audits
            WHERE asset_id = %s
            ORDER BY
                audit_timestamp DESC NULLS LAST,
                id DESC
            LIMIT 1
            """,
            (asset_id,)
        )

        audit = cur.fetchone()

        if not audit:

            cur.close()
            conn.close()

            return jsonify({
                "success": False,
                "message": "No audit result found for this endpoint"
            }), 404

        audit_id = audit[0]

        # -------------------------------------------------
        # GET AUDIT CHECKS
        # -------------------------------------------------

        cur.execute(
            """
            SELECT
                id,
                audit_id,
                check_id,
                check_name,
                category,
                expected_value,
                observed_value,
                status,
                severity,
                evidence
            FROM audit_checks
            WHERE audit_id = %s
            ORDER BY id
            """,
            (audit_id,)
        )

        check_rows = cur.fetchall()

        checks = []

        for row in check_rows:

            checks.append({
                "id": row[0],
                "audit_id": row[1],
                "check_id": row[2],
                "check_name": row[3],
                "category": row[4],
                "expected_value": row[5],
                "observed_value": row[6],
                "status": row[7],
                "severity": row[8],
                "evidence": row[9]
            })

        # -------------------------------------------------
        # CLOSE DATABASE
        # -------------------------------------------------

        cur.close()
        conn.close()

        # -------------------------------------------------
        # RETURN RESULT
        # -------------------------------------------------

        return jsonify({

            "audit_id": audit[0],

            "asset_id": audit[1],

            "hostname": audit[2],

            "operating_system": audit[3],

            "os_version": audit[4],

            "audit_profile": audit[5],

            "compliance_standard": audit[6],

            "audit_timestamp": (
                audit[7].isoformat()
                if audit[7]
                else None
            ),

            "overall_score": audit[8],

            "passed_count": audit[9],

            "failed_count": audit[10],

            "total_checks": audit[11],

            "status": audit[12],

            "checks": checks

        }), 200

    except Exception as e:

        print(
            "Get audit result error:",
            str(e)
        )

        return jsonify({
            "success": False,
            "message": "Failed to load audit result",
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
        host="0.0.0.0",
        port=5000,
        debug=True
    )