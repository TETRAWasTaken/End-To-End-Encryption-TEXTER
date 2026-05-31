# Server/secure_asgi_server.py
from fastapi import FastAPI, WebSocket, status, WebSocketDisconnect
import redis.asyncio as redis
import asyncio

# Import your existing modules
from database import StorageManager, DB_connect
from Server import Socket, caching as caching_module

app = FastAPI()

redis_client = redis.Redis(host='localhost', port=6379, db=0, decode_responses=True)

db_conn = DB_connect.DB_connect()
caching = caching_module.caching(db_conn)
storage_manager = StorageManager.StorageManager(db_conn)
print("Database connection established.")

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket, ticket: str = None):
    if not ticket:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    redis_key = f"ws_ticket:{ticket}"
    user_id = await redis_client.get(redis_key)

    if not user_id:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    await redis_client.delete(redis_key)

    await websocket.accept()
    
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
        print(f"WebSocket error for {user_id}: {e}")
    finally:
        print(f"Cleaning up active user {user_id}")
        caching.remove_active_user(websocket)