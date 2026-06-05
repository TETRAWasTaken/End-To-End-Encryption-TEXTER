#!/bin/bash

echo "========================================================"
echo "Stopping TEXTER Microservices..."
echo "========================================================"

echo "Stopping Rust Auth Server (Port 8001)..."
fuser -k 8001/tcp 2>/dev/null
echo "Rust Server stopped."

echo "Stopping Python WebSocket Server (Port 8002)..."
fuser -k 8002/tcp 2>/dev/null
echo "Python Server stopped."

echo "========================================================"
echo "All backend services have been cleanly shut down."
echo "========================================================"