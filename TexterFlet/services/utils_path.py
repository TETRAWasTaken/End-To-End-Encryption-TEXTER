import os
import sys
import platform


def get_app_data_dir():
    """Returns a writable directory for the database and keys."""
    try:
        # Check for Android specifically
        if "ANDROID_ARGUMENT" in os.environ:
            from jnius import autoclass  # type: ignore
            PythonActivity = autoclass('org.kivy.android.PythonActivity')
            activity = PythonActivity.mActivity
            return activity.getFilesDir().getAbsolutePath()
    except Exception:
        pass  # Fallback if jnius fails or not in Kivy environment

    # Generic fallback that works on Windows, Linux, Mac, and Flet-on-Android
    # os.path.expanduser("~") maps to the app's writable internal storage on Android.
    base_dir = os.path.expanduser("~")
    data_dir = os.path.join(base_dir, "texter_data")

    if not os.path.exists(data_dir):
        try:
            os.makedirs(data_dir)
        except OSError:
            # If expanding user failed, try a local folder (mostly for desktop dev)
            data_dir = os.path.join(os.getcwd(), "texter_data")
            if not os.path.exists(data_dir):
                os.makedirs(data_dir)

    return data_dir