import json
import os

"""
This class is meant for retrieval and manipulation of file storage
This class will later be updates to use a SQL based database managment system for better performance and security
"""

DIRECTORY_PATH = ".../TEXTER_ENCRYPTION_IMAGE/KeyStore"

class StorageManager:
    def __init__(self, user_id : str) -> None:
        self.user_id = user_id
        try:
            if not os.path.isdir(DIRECTORY_PATH):
                print("KeyStorage Directory not found, creating directory")
                os.mkdir(DIRECTORY_PATH)
            else:
                print("KeyStorage Directory found")
        except Exception as e:
            print(f"Error : {e} while initialising KeyStorage")

    def SaveKeyBundle(self, KeyBundle: dict, user_id : str) -> None:
        try:
            with open(os.path.join(DIRECTORY_PATH, f"{user_id}.json"), "w") as file:
                json.dump(KeyBundle, file)

        except Exception as e:
            print(f"Error : {e} while saving KeyBundle")

    def LoadKeyBundle(self, user_id : str) -> dict:
        try:
            with open(os.path.join(DIRECTORY_PATH, f"{user_id}.json"), "r") as file:
                KeyBundle = json.load(file)
                return KeyBundle
        except Exception as e:
            print(f"Error : {e} while loading KeyBundle")
            return {}