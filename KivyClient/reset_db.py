import os
from kivy.app import App


# We must define the class exactly as it is in your main.py
# so Kivy resolves the same user_data_dir path.
class TexterApp(App):
    pass


def clear_all_databases():
    print("--- Texter Database Cleanup Tool ---")

    # Initialize dummy app to resolve the path
    app = TexterApp()
    data_dir = app.user_data_dir

    print(f"Target Directory: {data_dir}")

    if not os.path.exists(data_dir):
        print("Data directory does not exist. No databases to clear.")
        return

    files_found = 0
    deleted_count = 0

    # Iterate and delete
    for filename in os.listdir(data_dir):
        if filename.endswith(".db") or filename.endswith(".db-journal"):
            files_found += 1
            full_path = os.path.join(data_dir, filename)
            try:
                os.remove(full_path)
                print(f"[OK] Deleted: {filename}")
                deleted_count += 1
            except Exception as e:
                print(f"[ERR] Failed to delete {filename}: {e}")

    if files_found == 0:
        print("No database files found.")
    else:
        print(f"Done. Deleted {deleted_count} of {files_found} database files.")


if __name__ == "__main__":
    clear_all_databases()