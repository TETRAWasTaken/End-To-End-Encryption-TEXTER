import os
import queue
import socket
import threading
import datetime
import json
import sys

class CACHEManager_Handler:
    def __init__(self):
        print("Initializing CACHEManager_Handler.")
        self.ACTIVEUSERS = None
        self.USERMATCH = {}
        self.credentials = {}
        self.data_initiation()

    def data_initiation(self):
        try:
            with open('text CACHE json.json', 'r') as file:
                self.CACHE = json.load(file)
                print("Loaded text CACHE.")
        except (FileNotFoundError, SyntaxError):
            print("No CACHE file found or invalid format. Creating new CACHE.")
            self.CACHE = {}  # Initialize empty CACHE if file doesn't exist

        try:
            with open("Credentials.json", "r") as f:
                self.credentials = json.load(f)

        except (FileNotFoundError, SyntaxError):
            print("Credential Data File not found, or invalid format, Exiting...")
            sys.exit(1)

        # Make sure all expected users exist in the CACHE
        for username in self.credentials.keys():
            username = username.strip('#')  # Remove # from username for CACHE key
            if username not in self.CACHE:
                self.CACHE[username] = {}
                print(f"Added {username} to CACHE.")

    def updateCache(self, user1, user2, text, flag):
        timestamp = str(datetime.datetime.now())
        try:
            self.CACHE[user2][timestamp] = [text, flag, user1]
        except KeyError:
            self.CACHE[user2] = {}
            self.CACHE[user2][timestamp] = [text, flag, user1]

    def getCache(self, user1, user2):
        try:
            return self.CACHE[user2]
        except KeyError:
            return False

    def online_Status(self, receiver, sender):
        if receiver in self.ACTIVEUSERS and self.USERMATCH[receiver] == sender:
            return True
        else:
            return False

    def user_Match(self, sender, receiver):
        self.USERMATCH[sender] = receiver
    def del_user_Match(self, sender):
        del self.USERMATCH[sender]

    def send_Text(self, reciever, text):
        thread_instance = self.ACTIVEUSERS[reciever]
        if hasattr(thread_instance, 'command_queue') and isinstance(thread_instance.command_queue, queue.Queue):
            command_payload = {'method': 'cmspromt', 'args': text}
            thread_instance.command_queue.put(command_payload)
        else:
            pass

    def update_Credentials(self):
        try:
            with open("Credentials.json", "w") as f:
                json.dump(self.credentials, f)
            print("Credentials updated.")
            for username in self.credentials.keys():
                username = username.strip('#')  # Remove # from username for CACHE key
                if username not in self.CACHE:
                    self.CACHE[username] = {}
                    print(f"Added {username} to CACHE.")
        except (FileNotFoundError, SyntaxError):
            print("Error Occured while updating Credentials.")
        except Exception as e:
            print(f"Error Occured while updating Credentials: {e}")

    def update_CACHE(self):
        try:
            with open('text cache json.json', 'w') as file:
                json.dump(self.CACHE, file)
            print("CACHE updated.")
        except (FileNotFoundError, SyntaxError):
            print("Error Occured while updating CACHE.")
        except Exception as e:
            print(f"Error Occured while updating CACHE: {e}")