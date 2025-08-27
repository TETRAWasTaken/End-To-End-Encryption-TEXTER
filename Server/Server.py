import asyncio
import json
import ssl

import websockets
import sys
import threading
import Socket as S
import cache_managment_system as CMS
import time
import os

Keystorage = os.path.join('../X3DH-Async-Protocol', 'KeyStorage')
Storagemanager = os.path.join('../X3DH-Async-Protocol', 'StorageManager')
Dbconnect = os.path.join('../X3DH-Async-Protocol', 'DB_connect')
sys.path.append(Dbconnect)
sys.path.append(Keystorage)
sys.path.append(Storagemanager)
import KeyStorage
import StorageManager
import DB_connect

class Server:
    def __init__(self):
        super().__init__()
        self.ssl_context = None
        self.host = '::1'
        self.users = []
        self.get_ssl_context()
        self.server_initiator()

    def server_initiator(self):
        self.DB = DB_connect.DB_connect()
        self.cms = CMS.CACHEManager_Handler()
        self.StorageManager = KeyStorage.StorageManager()
        self.credentials = self.cms.credentials
        print("Cache Management and Handler system activated")

        utc_Thread = threading.Thread(target=self.user_thread_checker)
        utc_Thread.daemon = True
        utc_Thread.start()

        try:
            asyncio.run(self.start_server())
        except KeyboardInterrupt:
            print("Server is shutting down.")
        except Exception as e:
            print(f"Error starting server: {e}")
            sys.exit(1)

    async def start_server(self):
        loop = asyncio.get_running_loop()
        print(f"Starting WebSocket server on {self.host}:12345 with SSL enabled. Waiting for connections...")
        async with websockets.serve(
            lambda websocket: self.connection_handler(websocket, loop),
            self.host,
            port = os.environ.get('PORT', 12345),
            ssl=self.ssl_context,
        ):
            await asyncio.Future()  # Run forever

    async def connection_handler(self, websocket, loop):
        addr = websocket.remote_address
        print(f"Connection from {addr} has been established, waiting for login or registration")
        authenticated_and_handled = False
        try:
            while not authenticated_and_handled:
                logorreg = await websocket.recv()

                if logorreg == 'login':
                    print(f"Login requested by {addr}")
                    cred = await websocket.recv()
                    cred = json.loads(cred)
                    user = cred['username']
                    passw = cred['password']

                    if not user or not passw:
                        print(f"Invalid credential format from {addr}")
                        await websocket.send("Invalid format")
                        return

                    try:
                        if self.credentials[user] == passw:
                            await websocket.send('1')

                            # Hand over to the threaded handler
                            socket_handler = S.Server(websocket=websocket, cms=self.cms, loop=loop, keyStorage=KeyStorage)
                            socket_handler.associated_thread = threading.Thread(target=socket_handler.start)
                            socket_handler.associated_thread.daemon = True
                            socket_handler.associated_thread.start()

                            self.users.append(user)
                            print(f"User {user} logged in and handed over to socket handler.")
                            authenticated_and_handled = True

                            # Keep this handler alive until the thread is done and the websocket is closed.
                            await websocket.wait_closed()

                        else:  # Password mismatch
                            print(f"Credentials don't match for client {addr}")
                            await websocket.send("Credfail")

                    except KeyError:
                        print(f"Account not found for {user if user else 'unknown'}")
                        await websocket.send("NAF")

                elif logorreg == 'reg':
                    print(f"Registration requested by {addr}")
                    cred = await websocket.recv()
                    cred = json.loads(cred)
                    user = cred['username']
                    passw = cred['password']

                    if not user or not passw:
                        print(f"Invalid registration format from {addr}")
                        await websocket.send("Invalid format")
                        return

                    if user in self.credentials.keys():
                        print(f"Registration failed, username {user} already exists")
                        await websocket.send('AAE')
                    else:
                        print(f"Registration successful for {user} from {addr}")
                        self.cms.update_Credentials(user, passw)
                        print(f"Updated self.credentials: {self.credentials}")
                        await websocket.send('success')

                        response = await websocket.recv()
                        if response == 'publish_keys':
                            key_bundle = await websocket.recv()
                            key_bundle = json.loads(key_bundle)
                            print(f"Received key bundle from {addr}, user_id - {user}")

                            try:
                                KeyStorage.StoreUserKeyBundle(user, key_bundle["identity_key"],
                                                              key_bundle["signed_pre_key"],
                                                              key_bundle["signed_pre_key_signature"],
                                                              key_bundle["one_time_pre_keys"])

                                print(f"Saved keys for {user} to database")
                                await websocket.send("keys_ok")
                            except Exception as e:
                                print(f"Error while saving keys for {user}: {e}")
                                await websocket.send("keys_fail")
                                return
                else:
                    print(f"Unknown command '{logorreg}' from {addr}")
                    await websocket.send("Unknown command")

        except websockets.exceptions.ConnectionClosed:
            print(f"Connection from {addr} closed during authentication.")
        except Exception as e:
            print(f"Error in connection_handler for {addr}: {e}")
        finally:
            if not authenticated_and_handled:
                await websocket.close()

    def user_thread_checker(self):
        while True:
            try:
                for i in list(self.cms.ACTIVEUSERS.keys()):
                    socket_handler_instance = self.cms.ACTIVEUSERS[i]
                    if not socket_handler_instance.associated_thread.is_alive():
                        socket_handler_instance.associated_thread.join(timeout=1.0)
                        self.cms.del_user_Match(i)
                        print(f"User {i} has been disconnected and all threads are cleared.")
                        del self.cms.ACTIVEUSERS[i]
                time.sleep(5)
            except (RuntimeError, KeyError) as e:
                print(f"Error in user_thread_checker: {e}")
                continue
            except Exception as e:
                print(f"Error : {e}")

    def get_ssl_context(self):
        try:
            self.ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            self.ssl_context.load_cert_chain(certfile='server.crt', keyfile='server.key')
        except Exception as e:
            print(f"Error while loading SSL context: {e}")
            sys.exit(1)

if __name__ == "__main__":
    Server()