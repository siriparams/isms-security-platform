from flask import Flask, request, jsonify
from flask_cors import CORS
import psycopg2
import os
from dotenv import load_dotenv

# Load values from .env
load_dotenv()

app = Flask(__name__)
CORS(app)


# PostgreSQL connection
def get_db_connection():
    return psycopg2.connect(
        host=os.getenv("DB_HOST"),
        database=os.getenv("DB_NAME"),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASSWORD"),
        port=os.getenv("DB_PORT")
    )


# Test PostgreSQL connection
try:
    conn = get_db_connection()
    print("PostgreSQL connected successfully!")
    conn.close()
except Exception as e:
    print("PostgreSQL connection failed:", e)


# Login API
@app.route("/login", methods=["POST"])
def login():
    data = request.json

    username = data.get("username")
    password = data.get("password")

    if username == "admin" and password == "admin123":
        return {
            "success": True,
            "message": "Login successful"
        }

    return {
        "success": False,
        "message": "Invalid username or password"
    }, 401


# Home route
@app.route("/")
def home():
    return "ISMS Backend is running!"

# Asset upload route
@app.route("/assets", methods=["POST"])
def add_asset():
    try:
        data = request.json

        conn = get_db_connection()
        cur = conn.cursor()

        cur.execute("""
            INSERT INTO assets
            (hostname, ip_address, operating_system, hardware,
             network, software, management, security_posture, user_context)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
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
        cur.close()
        conn.close()

        return {
            "message": "Asset added successfully",
            "asset_id": asset_id
        }, 201

    except Exception as e:
        return {
            "error": str(e)
        }, 500
        
# Start Flask server
if __name__ == "__main__":
    app.run(debug=True)