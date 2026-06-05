# Server/secure_asgi_server.py
import os
import traceback
from urllib.parse import urlparse
from fastapi import FastAPI, WebSocket, status, WebSocketDisconnect
import asyncio
import jwt

SECRET_KEY = os.environ.get("JWT_SECRET", "anshumaan-soni")
ALGORITHM = os.environ.get("ALGORITHM", "HS256")

# Import your existing modules
from database import StorageManager, DB_connect
from Server import Socket, caching as caching_module

app = FastAPI()

print("Initializing database connection for ASGI server...")
db_conn = DB_connect.DB_connect()
if db_conn.pool is None:
    print("WARNING: Database connection pool is None. Database connection failed!")
else:
    print("Database connection established.")
caching = caching_module.caching(db_conn)
storage_manager = StorageManager.StorageManager(db_conn)
print("ASGI Server caching and storage managers initialized.")

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket, ticket: str = None):
    if not ticket:
        print(f"WebSocket connection rejected: Missing ticket from {websocket.client}")
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return
    
    try:
        payload = jwt.decode(ticket, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload.get("sub")
        if not user_id:
            raise jwt.InvalidTokenError("user_id not found in token")
    
    except jwt.ExpiredSignatureError as e:
        print(f"Ticket expired for connection from {websocket.client}: {e}")
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return
    except jwt.InvalidTokenError as e:
        print(f"Invalid ticket for connection from {websocket.client}: {e}")
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    await websocket.accept()
    print(f"WebSocket connection accepted for user_id: {user_id}")
    
    caching.add_active_user(websocket, user_id, None)

    loop = asyncio.get_running_loop()
    socket_handler = Socket.Server(
        websocket=websocket,
        cache=caching,
        loop=loop,
        storage_manager=storage_manager
    )
    caching.update_active_user_handler(websocket, socket_handler)

    try:
        await asyncio.to_thread(caching.retrieve_cached_messages, receiver_id=user_id)
        await socket_handler.start()
    except WebSocketDisconnect:
        print(f"Client {user_id} disconnected.")
    except Exception as e:
        print(f"WebSocket error for {user_id}: {e}\n{traceback.format_exc()}")
    finally:
        print(f"Cleaning up active user {user_id}")
        caching.remove_active_user(websocket)