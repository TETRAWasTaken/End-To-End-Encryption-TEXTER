import asyncio
import json
import websockets
import sys
import threading
import re
import Socket as S
import cache_managment_system as CMS
import time

class Server:
    def __init__(self):
        super().__init__()
        self.host = '0.0.0.0'
        self.users = []
        self.server_initiator()

    def server_initiator(self):
        self.cms = CMS.CACHEManager_Handler()
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
        print(f"Starting WebSocket server on {self.host}:443")
        async with websockets.serve(
                lambda websocket: self.connection_handler(websocket, loop),
                self.host,
                443
        ):
            await asyncio.Future()  # Run forever

    async def connection_handler(self, websocket, loop):
        addr = websocket.remote_address
        print(f"Connection from {addr} has been established, waiting for login or registration")
        authenticated_and_handled = False
        try:
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
                        socket_handler = S.Server(websocket=websocket, cms=self.cms, loop=loop)
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
                    self.credentials[user] = passw
                    print(f"Updated self.credentials: {self.credentials}")
                    await websocket.send('success')
                    self.cms.update_Credentials()

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
            except AttributeError:
                continue


if __name__ == "__main__":
    Server()