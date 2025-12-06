import asyncio
import json
import base64
import websockets
from typing import Optional, Callable
from Server import caching
from database import StorageManager


def b64_encode(data: Optional[bytes]) -> Optional[str]:
    """
    Safely base64-encodes a bytes object into a string, handling None.

    Args:
        data: The bytes object to encode.

    Returns:
        The base64-encoded string, or None if the input was None.
    """
    if data is None: return None
    return base64.b64encode(data).decode("utf-8")


def to_bytes(data) -> Optional[bytes]:
    """
    Safely converts memoryview or bytes to bytes, handling None.

    Args:
        data: The memoryview or bytes object to convert.

    Returns:
        The converted bytes object, or None if the input was None.
    """
    if data is None: return None
    return bytes(data)


class Server:
    """
    Manages a WebSocket connection for a single client, handling asynchronous
    communication and command processing for a secure chat application.

    This class is responsible for listening for incoming messages, processing
    commands, and interacting with other parts of the server infrastructure
    like caching and database storage. It uses an asynchronous, queue-based
    approach to handle long-running or blocking operations in separate threads,
    ensuring the main WebSocket server remains responsive.
    """
    def __init__(self, websocket,
                 cache: caching.caching,
                 loop: asyncio.AbstractEventLoop,
                 storage_manager: StorageManager.StorageManager):
        """
        Initializes a new Server instance for a client connection.

        Args:
            websocket: The WebSocket connection object for the client.
            cache: An instance of the caching class for managing active users
                     and message caching.
            loop: The asyncio event loop used for scheduling asynchronous tasks.
            storage_manager: An instance of the StorageManager for database
                             interactions.
        """
        self.websocket = websocket
        self.caching = cache
        self.loop = loop
        self.StorageManager = storage_manager
        self.command_queue = asyncio.Queue()
        self.kill_signal = False
        self.receiver = None
        self.user_id = None
        self.finished = asyncio.Event()

        if self.caching is None:
            raise ValueError("Caching object is not initialized")

    async def _process_command(self) -> None:
        """
        Asynchronous consumer that processes commands from the command queue.

        This method continuously waits for commands to be added to the queue
        and offloads their execution to a separate thread to prevent blocking
        the main asyncio event loop.
        """
        while not self.kill_signal:
            try:
                command_payload = await self.command_queue.get()
                await asyncio.to_thread(self._execute_sync_command, command_payload)
                self.command_queue.task_done()
            except asyncio.CancelledError:
                break
            except Exception as e:
                print(f"Error in _process_command: {e}")

    def _execute_sync_command(self, command_payload: dict):
        """
        Executes a command synchronously in a separate thread.

        Args:
            command_payload: A dictionary containing the 'method' to be called
                             and its 'args'.
        """
        method_name = command_payload.get("method")
        args = command_payload.get("args")

        if method_name:
            target_method: Optional[Callable] = getattr(self, method_name, None)
            if target_method and callable(target_method):
                if args is not None:
                    target_method(args)
                else:
                    target_method()

    async def start(self) -> None:
        """
        Initiates the client communication interface.

        This is the main entry point for the socket handler. It retrieves the
        user ID, starts the message listener and command processor tasks, and
        waits for the connection to be closed.
        """
        try:
            user_info = self.caching.get_active_user_info(self.websocket)
            if user_info:
                self.user_id = user_info[0]
                listener_task = asyncio.create_task(self.listen())
                processor_task = asyncio.create_task(self._process_command())
                await self.finished.wait()
                listener_task.cancel()
                processor_task.cancel()
            else:
                raise KeyError("User not found in ACTIVEUSERS immediately after start.")
        except Exception as e:
            print(f"Error in Socket.Server.start for {self.user_id}: {e}")
        finally:
            print(f"Socket instance for {self.user_id or self.websocket.remote_address} is shutting down.")
            self.kill_signal = True
            self.finished.set()

    async def listen(self) -> None:
        """
        Listens for incoming messages from the WebSocket connection.

        This method runs in a loop, processing messages as they arrive. It
        deserializes the JSON payload and puts the corresponding command into
        the command queue for processing.
        """
        try:
            async for payload_str in self.websocket:
                try:
                    payload = json.loads(payload_str)
                    cmd = payload.get("command")
                    status = payload.get("status")
                    command_payload = None

                    if cmd == "friend_request":
                        command_payload = {'method': 'handle_friend_request', 'args': payload}
                    elif cmd == "get_pending_friend_requests":
                        command_payload = {'method': 'handle_get_pending_friend_requests', 'args': None}
                    elif cmd == "accept_friend_request":
                        command_payload = {'method': 'handle_accept_friend_request', 'args': payload}
                    elif status == "Encrypted":
                        command_payload = {'method': 'recv_text', 'args': payload}
                    elif status == "User_Select":
                        command_payload = {'method': 'select_user', 'args': payload}
                    elif status == "request_key_bundle":
                        command_payload = {'method': 'handle_key_bundle_request', 'args': payload}

                    if command_payload:
                        self.command_queue.put_nowait(command_payload)
                except json.JSONDecodeError:
                    print(f"Invalid JSON from {self.user_id}")
                    continue
        except (websockets.exceptions.ConnectionClosed, ConnectionError):
            print(f"Client {self.user_id} disconnected.")
        except Exception as e:
            print(f"Unexpected error in listen for {self.user_id}: {e}")
        finally:
            self.kill_signal = True
            self.finished.set()

    def queue_external_command(self, payload: dict):
        """
        Thread-safe helper to queue a command from an external thread.

        Args:
            payload: The command payload to add to the queue.
        """
        self.loop.call_soon_threadsafe(self.command_queue.put_nowait, payload)

    def recv_text(self, recv_payload: dict):
        """
        Processes a received text message and forwards it to the recipient.

        Args:
            recv_payload: The payload containing the message, sender, and
                          recipient information.
        """
        message = recv_payload.get("message").get("text")
        recv_id = recv_payload.get("message").get("recv_user_id")
        sender_id = recv_payload.get("message").get("sender_user_id")
        try:
            if self.caching.send_text(sender_id, recv_id, message):
                print(f"Text sent to {recv_id} from {sender_id}")
            else:
                print(f"User {recv_id} is offline. Message from {sender_id} has been cached.")
        except Exception as e:
            print(f"Error in caching.send_text: {e}")

    def send_text(self, msg_payload: dict):
        """
        Sends a text message payload to the connected client.

        Args:
            msg_payload: The JSON payload to send to the client.
        """
        try:
            asyncio.run_coroutine_threadsafe(self.websocket.send(json.dumps(msg_payload)), self.loop)
        except Exception as e:
            print(f"Error in socket.send_text: {e}")

    def select_user(self, user_payload: dict):
        """
        Handles a user selection event from the client.

        This method checks if the selected user is a friend and is online,
        and then initiates the retrieval of any cached messages.

        Args:
            user_payload: The payload containing the user_id of the selected
                          partner.
        """
        partner_id = user_payload.get("user_id")
        try:
            if not self.caching.check_credentials(partner_id):
                payload = self.caching.payload("User_Select", 'User Not Available')
                asyncio.run_coroutine_threadsafe(self.websocket.send(payload), self.loop)
                return

            if self.StorageManager.CheckFriendsStatus(self.user_id, partner_id):
                if self.caching.get_active_user_websocket(partner_id):
                    payload = self.caching.payload("User_Select", 'User Available And Friends')
                    self.receiver = partner_id
                else:
                    payload = self.caching.payload("User_Select", 'User Not Online but Friends')

                asyncio.run_coroutine_threadsafe(self.websocket.send(payload), self.loop)
                print(f"User {self.user_id} selected {partner_id}. Retrieving cached messages.")
                self.caching.retrieve_cached_messages(self.user_id, partner_id)
            else:
                payload = self.caching.payload('User_Select', 'User Not Friend')
                asyncio.run_coroutine_threadsafe(self.websocket.send(payload), self.loop)
        except Exception as e:
            print(f"Error in select_user: {e}")

    def handle_key_bundle_request(self, payload: dict):
        """
        Handles a request for a partner's key bundle.

        Args:
            payload: The payload containing the user_id of the partner whose
                     key bundle is requested.
        """
        partner_id = payload.get("user_id")
        if not partner_id or not self.user_id:
            return

        try:
            if not self.StorageManager.CheckFriendsStatus(self.user_id, partner_id):
                fail_payload = self.caching.payload("key_bundle_fail", "not_friends")
                asyncio.run_coroutine_threadsafe(self.websocket.send(fail_payload), self.loop)
                return

            key_bundle = self.StorageManager.LoadKeyBundle(partner_id)
            if not key_bundle or not key_bundle.get("identity_key"):
                fail_payload = self.caching.payload("key_bundle_fail", "no_key_bundle")
                asyncio.run_coroutine_threadsafe(self.websocket.send(fail_payload), self.loop)
            else:
                success_payload = self.caching.payload("key_bundle_ok", key_bundle)
                asyncio.run_coroutine_threadsafe(self.websocket.send(success_payload), self.loop)

        except Exception as e:
            print(f"Error in handle_key_bundle_request: {e}")
            error_payload = self.caching.payload("key_bundle_fail", "server_error")
            asyncio.run_coroutine_threadsafe(self.websocket.send(error_payload), self.loop)

    def handle_friend_request(self, payload: dict):
        """
        Handles an incoming friend request from a user.

        Args:
            payload: The payload containing the 'from_user' and 'to_user' IDs.
        """
        from_user = payload.get("from_user")
        to_user = payload.get("to_user")

        if not from_user or not to_user:
            return

        try:
            success = self.StorageManager.CreateFriendRequest(from_user, to_user)

            if success:
                response = self.caching.payload("friend_request_status", "sent")
                asyncio.run_coroutine_threadsafe(self.websocket.send(response), self.loop)

                target_websocket = self.caching.get_active_user_websocket(to_user)
                if target_websocket:
                    target_user_info = self.caching.get_active_user_info(target_websocket)
                    if target_user_info and target_user_info[1]:
                        target_socket_handler = target_user_info[1]
                        notification = self.caching.payload("newx_friend_request", {"from": from_user})
                        notification_dict = json.loads(notification)
                        command_payload = {'method': 'send_text', 'args': notification_dict}

                        if hasattr(target_socket_handler, 'queue_external_command'):
                            target_socket_handler.queue_external_command(command_payload)
            else:
                response = self.caching.payload("friend_request_status", "failed")
                asyncio.run_coroutine_threadsafe(self.websocket.send(response), self.loop)

        except Exception as e:
            print(f"Error in handle_friend_request: {e}")
            response = self.caching.payload("friend_request_status", "error")
            asyncio.run_coroutine_threadsafe(self.websocket.send(response), self.loop)

    def handle_get_pending_friend_requests(self, payload: dict = None):
        """
        Fetches and sends a list of pending friend requests to the client.

        Args:
            payload: This argument is not used but is kept for consistency.
        """
        if not self.user_id:
            return

        try:
            pending_requests = self.StorageManager.GetPendingFriendRequests(self.user_id)
            response = self.caching.payload("pending_friend_requests", pending_requests)
            asyncio.run_coroutine_threadsafe(self.websocket.send(response), self.loop)
        except Exception as e:
            print(f"Error in handle_get_pending_friend_requests: {e}")

    def handle_accept_friend_request(self, payload: dict):
        """
        Handles the acceptance of a friend request and notifies both users.

        Args:
            payload: The payload containing the 'from_user' and 'to_user' IDs.
        """
        from_user = payload.get("from_user")
        to_user = payload.get("to_user")

        if not from_user or not to_user or to_user != self.user_id:
            return

        try:
            success = self.StorageManager.AcceptFriendRequest(from_user, to_user)

            if success:
                response_to_acceptor = self.caching.payload("friend_request_accepted", {"friend_username": from_user})
                asyncio.run_coroutine_threadsafe(self.websocket.send(response_to_acceptor), self.loop)

                target_websocket = self.caching.get_active_user_websocket(from_user)
                if target_websocket:
                    target_user_info = self.caching.get_active_user_info(target_websocket)
                    if target_user_info and target_user_info[1]:
                        target_socket_handler = target_user_info[1]

                        notification_to_sender = self.caching.payload("friend_request_accepted",
                                                                      {"friend_username": to_user})
                        notification_dict = json.loads(notification_to_sender)

                        command_payload = {'method': 'send_text', 'args': notification_dict}

                        if hasattr(target_socket_handler, 'queue_external_command'):
                            target_socket_handler.queue_external_command(command_payload)
            else:
                response = self.caching.payload("friend_request_accepted_status", "failed")
                asyncio.run_coroutine_threadsafe(self.websocket.send(response), self.loop)

        except Exception as e:
            print(f"Error in handle_accept_friend_request: {e}")
            response = self.caching.payload("friend_request_accepted_status", "error")
            asyncio.run_coroutine_threadsafe(self.websocket.send(response), self.loop)