import queue
import asyncio
from queue import Queue
import base64
import websockets
import threading
import time
from typing import Optional, Callable
from NewServerCode import caching
import json
from database import KeyStorage

class Server:
    def __init__(self, websocket,
                 caching: caching.caching,
                 loop: asyncio.AbstractEventLoop,
                 keystorage: KeyStorage.KeyStorage):
        self.websocket = websocket
        self.caching = caching
        self.loop = loop
        self.KeyStorage = keystorage
        self.command_queue = queue.Queue()
        self.associated_threads = None
        self.kill_signal = False
        self.receiver = None # The user on other end of the conversation
        self.user_id = None # The user id of the current user
        if self.caching is None:
            quit()

    def _process_command(self) -> None:
        """
        Processes command payload, which allows other methods to run the internal methods of this class.
        :return: None
        """
        while not self.kill_signal:
            try:
                command_payload = self.command_queue.get()
                method_name = command_payload.get("method")
                args = command_payload.get("args", ())

                if method_name:
                    target_method: Optional[Callable] = getattr(self, method_name, None)
                    if target_method and callable(target_method):
                        target_method(args)
                    else:
                        continue
                self.command_queue.task_done()
            except Exception as e:
                print(f"Error in _process_command: {e}")
                pass

    def start(self) -> None:
        """
        Initiates the client communication interface
        :return None:
        """
        print(f"Socket instance started for websocket {self.websocket.remote_address}")
        try:
            self.user_id = self.caching.ACTIVEUSERS[self.websocket][0]
            user_info = self.caching.get_active_user_info(self.websocket) # Use thread-safe method
            if user_info:
                self.user_id = user_info[0]
                self.processing()
            else:
                raise KeyError("User not found in ACTIVEUSERS after authentication.")
        except KeyError:
             print(f"Error: User not found in ACTIVEUSERS for websocket {self.websocket.remote_address}. Closing connection.")
        except Exception as e:
            print(f"Error in Socket.Server.start: {e}")
        finally:
            print(f"Socket instance for {self.user_id or self.websocket.remote_address} is shutting down.")
            self.kill_signal = True # Ensure all loops in threads terminate
            asyncio.run_coroutine_threadsafe(self.websocket.close(), self.loop)

    def processing(self) -> None:
        """
        Initiates the further communication process with the client.
        :return None:
        """
        listener_thread = threading.Thread(target=self.listen)
        processor_thread = threading.Thread(target=self._process_command)

        listener_thread.start()
        processor_thread.start()
        
        # Block until the listener thread terminates (on disconnect)
        listener_thread.join()
        processor_thread.join()

    def listen(self) -> None:
        """
        Listens to the client and processes the received messages.
        """
        try:
            while not self.kill_signal:
                future = asyncio.run_coroutine_threadsafe(self.websocket.recv(), self.loop)
                payload = future.result()
                payload = json.loads(payload)

                if payload.get("status") == "Encrypted":
                    command_payload = {'method': 'recv_text', 'args': payload}
                    self.command_queue.put(command_payload)

                elif payload.get("status") == "User_Select":
                    command_payload = {'method': 'select_user', 'args': payload}
                    self.command_queue.put(command_payload)

                elif payload.get("status") == "request_key_bundle":
                    command_payload = {'method': 'handle_key_bundle_request', 'args': payload}
                    self.command_queue.put(command_payload)
        except (ConnectionError, websockets.exceptions.ConnectionClosed) as e:
            print(f"Client {self.user_id} disconnected: {e}")
        except Exception as e:
            print(f"Unexpected error in listen thread for {self.user_id}: {e}")
        finally:
            self.kill_signal = True


    def recv_text(self, recv_payload: dict):
        """
        Processes the received text from the current client
         and redirects to the correct user
        :param recv_payload:
        """
        message = recv_payload.get("message").get("text")
        recv_id = recv_payload.get("message").get("recv_user_id")
        sender_id = recv_payload.get("message").get("sender_user_id")
        try:
            if self.caching.send_text(sender_id, recv_id, message):
                print(f"Text sent to {recv_id} from {sender_id}")
            else:
                print(f"Error while sending text to {recv_id} from {sender_id}")
        except Exception as e:
            print(f"Error in caching.send_text: {e}")

    def send_text(self, msg_payload: dict):
        """
        Send the text to the client
        :param msg_payload:
        """
        try:
            asyncio.run_coroutine_threadsafe(self.websocket.send(json.dumps(msg_payload)), self.loop)
        except Exception as e:
            print(f"Error in socket.send_text: {e}")
            pass


    def select_user(self, user_payload: dict):
        """
        Processes the selected user from the client, and redirects to the correct user
        :param user_payload:
        """
        user_id = user_payload.get("user_id")
        try:
            # First, check if the user even exists in the database
            if not self.caching.check_credentials(user_id):
                payload = self.caching.payload("User_Select", 'User Not Available') # Using client's expected message
                asyncio.run_coroutine_threadsafe(self.websocket.send(payload), self.loop)
                return

            # Now check if the existing user is online
            if self.caching.get_active_user_websocket(user_id): # Use thread-safe method
                payload = self.caching.payload("User_Select", 'User Available') # Using client's expected message
                self.receiver = user_id
                self.caching.retrieve_text_cache(self.receiver, self.user_id)
            else:
                payload = self.caching.payload('User_Select', 'User Not Available') # Using client's expected message
            asyncio.run_coroutine_threadsafe(self.websocket.send(payload), self.loop)

        except Exception as e:
            print(f"Error in caching.select_user: {e}")

    def handle_key_bundle_request(self, payload: dict):
        """
        Fetches and send the key bundle to the client
        """
        partner_id = payload.get("user_id")
        if not partner_id:
            return

        print(f"Sending KeyBundle of {partner_id} to {self.user_id}")
        try:
            key_bundle = self.KeyStorage.LoadUserKeyBundle(partner_id)
            if not key_bundle or not key_bundle.get("identity_key"):
                payload = self.caching.payload("key_bundle_fail", "no_key_bundle")
            else:
                def b64_encode(data):
                    if data is None: return None
                    return base64.b64encode(data).decode("utf-8")

                serializable_bundle = {
                    "identity_key": b64_encode(key_bundle.get("identity_key")),
                    "signed_pre_key": b64_encode(key_bundle.get("signed_pre_key")),
                    "signature": b64_encode(key_bundle.get("signature")),
                    "one_time_pre_key": b64_encode(key_bundle.get("one_time_pre_key")),
                    "one_time_key_id": key_bundle.get("one_time_key_id"),
                    "user_id": partner_id,
                }
                payload = self.caching.payload("key_bundle_ok", serializable_bundle)

            asyncio.run_coroutine_threadsafe(self.websocket.send(json.dumps(payload)), self.loop)

        except Exception as e:
            print(f"Error in caching.handle_key_bundle_request: {e}")
            payload = self.caching.payload("key_bundle_fail", "no_key_bundle")
            asyncio.run_coroutine_threadsafe(self.websocket.send(json.dumps(payload)), self.loop)
