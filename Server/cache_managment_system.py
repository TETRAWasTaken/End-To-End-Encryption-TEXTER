import psycopg2
import queue
import threading
import datetime
import json

from X3DH import DB_connect as DB

class CACHEManager_Handler:
    def __init__(self, DB: DB.DB_connect):
        print("Initializing CACHEManager_Handler.")
        self.db_connector = DB
        self.ACTIVEUSERS = {}
        self.USERMATCH = {}
        self.credentials = {}
        self._lock = threading.Lock()
        self.load_credentials()
        self.data_initiation()

    def payload(self, status: str, message: str) -> json.dumps:
        """
        Describes the general payload of each message sent between Server and Client
        :param status: The basic code of sent message, can be "error", "ok"
        :param message: The extra details that needs to be sent
        :return payload: A JSON object containing the status and message
        """

        payload = {
            "status": status,
            "message": message
        }
        return json.dumps(payload)

    def load_credentials(self):
        """
        Loads all user credentials from the PostgreSQL database into the in-memory
        self.credentials dictionary.
        """

        if not self.db_connector.pool:
            print("Database connection pool is not available. Cannot load credentials.")
            return

        conn = None
        try:
            conn = self.db_connector.pool.getconn()
            with conn.cursor() as cur:
                # Assuming a table named 'credentials' with 'username' and 'password' columns
                cur.execute("SELECT user_id, password FROM user_info")
                records = cur.fetchall()
                with self._lock:
                    self.credentials.clear()
                    for record in records:
                        username, password = record
                        self.credentials[username] = password
            print("Successfully loaded user credentials from the database.")
        except (Exception, psycopg2.DatabaseError) as e:
            print(f"Error loading credentials from database: {e}")
            self.credentials = {}  # Ensure credentials cache is empty on error
        finally:
            if conn:
                self.db_connector.pool.putconn(conn)

    def data_initiation(self):
        with self._lock:
            try:
                with open('text cache json.json', 'r') as file:
                    self.CACHE = json.load(file)
                    print("Loaded text CACHE.")
            except (FileNotFoundError, SyntaxError):
                print("No CACHE file found or invalid format. Creating new CACHE.")
                self.CACHE = {}  # Initialize empty CACHE if file doesn't exist

            # Make sure all expected users exist in the CACHE
            for username in self.credentials.keys():
                username = username.strip('#')  # Remove # from username for CACHE key
                if username not in self.CACHE:
                    self.CACHE[username] = {}
                    print(f"Added {username} to CACHE.")

    def updateCache(self, user1, user2, text, flag):
        with self._lock:
            timestamp = str(datetime.datetime.now())
            # FIX: Standardize usernames by stripping the '#' before caching.
            sender = user1.strip('#')
            receiver = user2.strip('#')
            try:
                self.CACHE[receiver][timestamp] = [text, flag, sender]
            except KeyError:
                self.CACHE[receiver] = {}
                self.CACHE[receiver][timestamp] = [text, flag, sender]

    def getCache(self, user1):
        with self._lock:
            try:
                return self.CACHE[user1]
            except KeyError:
               return False

    def online_Status(self, receiver, sender):
        with self._lock:
            if receiver in self.ACTIVEUSERS and self.USERMATCH[receiver] == sender:
                return True
            else:
                return False

    def user_Match(self, sender, receiver):
        with self._lock:
            self.USERMATCH[sender] = receiver

    def del_user_Match(self, sender):
        with self._lock:
            try:
                del self.USERMATCH[sender]
            except KeyError:
                pass

    def send_Text(self, reciever, text):
        with self._lock:
            thread_instance = self.ACTIVEUSERS[reciever]
            if hasattr(thread_instance, 'command_queue') and isinstance(thread_instance.command_queue, queue.Queue):
                command_payload = {'method': 'cmspromt', 'args': text}
                thread_instance.command_queue.put(command_payload)
                return True
            else:
                print(f"Error: No command queue found for {reciever}.")
                return False

    def update_Credentials(self, username, password):
        """
        Adds a new user credential to the database and then updates the in-memory cache.
        This operation is thread-safe.
        Returns True on success, False on failure.
        """
        if not self.db_connector.pool:
            print("Database connection pool is not available. Cannot add credential.")
            return False

        # First, check if the user already exists in the cache to avoid a DB hit
        with self._lock:
            if username in self.credentials:
                return False

        conn = None
        try:
            conn = self.db_connector.pool.getconn()
            with conn.cursor() as cur:
                # Insert the new credential into the database
                cur.execute(
                    "INSERT INTO user_info (user_id, password) VALUES (%s, %s)",
                    (username, password)
                )
                conn.commit()

                # If the DB insert is successful, update the in-memory cache
                with self._lock:
                    self.credentials[username] = password

                print(f"New user '{username}' credentials saved to database and cache.")
                return True
        except (Exception, psycopg2.DatabaseError) as e:
            print(f"Error adding credential to database for user '{username}': {e}")
            if conn:
                conn.rollback()
            return False
        finally:
            if conn:
                self.db_connector.pool.putconn(conn)

    def update_CACHE(self):
        try:
            with open('text cache json.json', 'w') as file:
                json.dump(self.CACHE, file)
            print("CACHE updated.")
        except (FileNotFoundError, SyntaxError):
            print("Error Occured while updating CACHE.")
        except Exception as e:
            print(f"Error Occured while updating CACHE: {e}")