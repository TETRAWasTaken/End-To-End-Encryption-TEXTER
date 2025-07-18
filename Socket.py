import queue
import asyncio
import websockets
import threading
import time
from typing import Optional, Callable
import cache_managment_system as CMS


class Server:
    def __init__(self, websocket, cms: CMS.CACHEManager_Handler, loop: asyncio.AbstractEventLoop):
        self.websocket = websocket
        self.cms = cms
        self.loop = loop
        self.command_queue = queue.Queue()
        self.servernames = []
        self.associated_threads = None
        self.kill_signal = False
        if self.cms is None:
            quit()

    def _process_command(self):
        while not self.kill_signal:
            try:
                command_payload = self.command_queue.get_nowait()
                method_name = command_payload.get("method")
                args = command_payload.get("args", ())

                if method_name:
                    target_method: Optional[Callable] = getattr(self, method_name, None)
                    if target_method and callable(target_method):
                        target_method(args)
                    else:
                        continue
                self.command_queue.task_done()
            except queue.Empty:
                continue
            except Exception as e:
                print(f"Error in _process_command: {e}")
                pass

    def start(self):
        print(f"Socket instance started for websocket {self.websocket.remote_address}")
        try:
            self.handle_client()
        except Exception as e:
            print(f"Error in Socket.Server.start: {e}")
        finally:
            if not self.websocket.close:
                asyncio.run_coroutine_threadsafe(self.websocket.close(), self.loop)
            username = self.servernames[0] if self.servernames else 'unknown user'
            print(f"Socket instance for {username} has finished.")

    def handle_client(self):
        try:
            # Block this thread until we receive user2 from the client
            future_user2 = asyncio.run_coroutine_threadsafe(self.websocket.recv(), self.loop)
            user2 = future_user2.result()

            # Block this thread until we receive user1 from the client
            future_user1 = asyncio.run_coroutine_threadsafe(self.websocket.recv(), self.loop)
            user1 = future_user1.result()

            self.servernames.append(user1)
            self.servernames.append(user2)

            self.cms.ACTIVEUSERS[user1] = self

            self.processing()
        except (websockets.exceptions.ConnectionClosed, websockets.exceptions.ConnectionClosedError):
            print("Connection closed during user info handshake.")
        except Exception as e:
            print(f"Error in handle_client: {e}")

    def processing(self):
        user = self.servernames[0]
        user2 = self.servernames[1]
        self.cms.user_Match(user, user2)

        prompt_thread = threading.Thread(target=self.prompt)
        cache_thread = threading.Thread(target=self.tcachepromt, args=(user, user2))
        cmd_thread = threading.Thread(target=self._process_command)

        prompt_thread.start()
        cache_thread.start()
        cmd_thread.start()

        # Block the main execution thread of this object until the I/O threads are done
        prompt_thread.join()
        cache_thread.join()
        cmd_thread.join()

        print(f"All threads for user {user} have been joined. Connection is closed.")

    def prompt(self):  # Handles receiving messages
        user = self.servernames[0]
        user2 = self.servernames[1]
        while not self.kill_signal:
            try:
                # Block this thread until a message is received
                future = asyncio.run_coroutine_threadsafe(self.websocket.recv(), self.loop)
                received_data = future.result()

                if self.cms.online_Status(user2, user):
                    if self.cms.send_Text(user2, received_data):
                        self.cms.updateCache(user, user2, received_data, 1)
                        print(f"Message sent to {user2} from {user}")
                    else:
                        self.cms.updateCache(user, user2, received_data, 0)
                else:
                    self.cms.updateCache(user, user2, received_data, 0)
                self.cms.update_CACHE()
            except (websockets.exceptions.ConnectionClosed, websockets.exceptions.ConnectionClosedError):
                print(f"Connection closed by {user}. Prompt thread exiting.")
                self.kill_signal = True
                break
            except Exception as e:
                print(f"Error in prompt thread for {user}: {e}")
                self.kill_signal = True
                break

    def tcachepromt(self, user, user2):  # Handles sending cached messages
        self.tcache = self.cms.getCache(user)
        if not self.tcache:
            print(f"Could not fetch cache for {user} from {user2}.")
            return

        while not self.kill_signal:
            try:
                for i in list(self.tcache.keys()):
                    if self.tcache[i][2] == user2 and self.tcache[i][1] == 0:
                        time.sleep(0.1)
                        try:
                            text_to_send = self.tcache[i][0]
                            asyncio.run_coroutine_threadsafe(self.websocket.send(text_to_send), self.loop)
                            self.tcache[i][1] = 1  # Mark as sent
                        except Exception as send_error:
                            print(f"Error sending from tcachepromt: {send_error}")
                            continue
            except RuntimeError as e:
                print(f"Runtime error in tcachepromt (cache likely modified during iteration): {e}")
                time.sleep(1)
                continue
            except Exception as e:
                print(f"An unexpected error occurred in tcachepromt: {e}")
                break

    def cmspromt(self, text):  # Handles sending push messages from the cache system
        try:
            asyncio.run_coroutine_threadsafe(self.websocket.send(text), self.loop)
        except Exception as e:
            print(f"Error in cmspromt: {e}")
            pass