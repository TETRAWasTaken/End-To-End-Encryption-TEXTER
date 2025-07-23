import os

class DirectoryManager:
    def __init__(self):
        self.directory = os.getcwd()

    def create_Directory(self, directory_name):
        try:
            os.mkdir(directory_name)
            print(f"Directory '{directory_name}' created successfully.")
        except FileExistsError:
            print(f"Directory '{directory_name}' already exists.")

    def delete_Directory(self, directory_name):
        try:
            os.rmdir(directory_name)
            print(f"Directory '{directory_name}' deleted successfully.")
        except FileNotFoundError:
            print(f"Directory '{directory_name}' not found.")
        except OSError:
            print(f"Directory '{directory_name}' is not empty.")

    def check_Directory(self, directory_name):
        try:
            if directory_name in os.listdir():
                return True
            else:
                return False
        except FileNotFoundError:
            print(f"Directory '{directory_name}' not found.")
        except Exception as e:
            print(f"An error occurred while checking directory: {e}")

