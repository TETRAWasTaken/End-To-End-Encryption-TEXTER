#!/bin/bash

# ==============================================================================
# CONFIGURATION & ENVIRONMENT VARIABLES
# ==============================================================================

# --- Variables for Rust Auth Server ---
# Rust SQLx parses this as a URI, so any '@' in the password MUST be encoded as '%40'
export DATABASE_URL="postgres://anshumaansoni:Texter%400246@texterdb.postgres.database.azure.com:5432/textere2ee?sslmode=require"


# --- Variables for Python WebSocket Server ---
# Python handles these fields individually, so use the RAW password here (keep the '@' literal!)
export DB_HOST="texterdb.postgres.database.azure.com"
export DB_PORT="5432"
export DB_USER="anshumaansoni"
export DB_PASSWORD="Texter%400246"
export DB_NAME="textere2ee"

# Note: If your Python code expects different variable names (e.g., POSTGRES_USER 
# or DB_PASS), simply change the left-side names above to match your DB_connect.py file.


# --- Shared Security Keys ---
export JWT_SECRET="anshumaan-soni"
export ALGORITHM="HS256"


# --- Log Configurations ---
RUST_LOG_FILE="rust_server.log"
PYTHON_LOG_FILE="python_server.log"

echo "========================================================"
echo "Initializing TEXTER Microservices Stack..."
echo "========================================================"

# ==============================================================================
# 1. START RUST AUTH SERVER (PORT 8001)
# ==============================================================================
echo "Checking port 8001..."
fuser -k 8001/tcp 2>/dev/null || true 

if [ -f "./AuthServer/target/debug/AuthServer" ]; then
    echo "Starting Rust Auth Server on port 8001..."
    chmod +x ./AuthServer/target/debug/AuthServer
    export PORT=8001
    nohup ./AuthServer/target/debug/AuthServer > "$RUST_LOG_FILE" 2>&1 &
    echo "▶ Rust Server running in background."
else
    echo "ERROR: 'AuthServer' not found!"
    exit 1
fi

# ==============================================================================
# 2. START PYTHON WEBSOCKET SERVER (PORT 8002)
# ==============================================================================
echo "Checking port 8002..."
fuser -k 8002/tcp 2>/dev/null || true 

# source venv/bin/activate # Uncomment if using a virtual environment

echo "Starting Python ASGI Server on port 8002..."
nohup .venv/bin/python3 -m uvicorn Server.secure_asgi_server:app --host 127.0.0.1 --port 8002 > "$PYTHON_LOG_FILE" 2>&1 &

echo "▶ Python Server running in background."
echo "========================================================"
echo "Setup complete! Monitor logs via 'tail -f *.log'"
echo "========================================================"
