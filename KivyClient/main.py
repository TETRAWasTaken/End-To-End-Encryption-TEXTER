from kivy.config import Config

# Disable multi-touch simulation (red dots) for better desktop experience
Config.set('input', 'mouse', 'mouse')
Config.set('graphics', 'width', '400')
Config.set('graphics', 'height', '600')

from kivy.app import App
from kivy.core.window import Window
from kivy.uix.screenmanager import ScreenManager, Screen
from kivy.clock import Clock
from kivy.uix.label import Label
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.behaviors import ButtonBehavior
from kivy.properties import StringProperty, BooleanProperty
from service.app_controller import AppController


# --- Custom Widget Classes (Fixes Click/Binding Issues) ---

class ContactButton(ButtonBehavior, BoxLayout):
    text = StringProperty('')

    def on_release(self):
        # Directly call app selection logic
        app = App.get_running_app()
        app.select_partner(self.text)
        return super().on_release()


class RequestBox(BoxLayout):
    username = StringProperty('')


class MessageLabel(Label):
    is_me = BooleanProperty(False)


# --- Screens ---

class LoginScreen(Screen):
    def on_enter(self):
        if Window.width > 500:
            Window.size = (400, 600)


class ChatScreen(Screen):
    def on_enter(self):
        Window.size = (1000, 700)
        # Center the window
        Window.left = (Window.system_size[0] - 1000) / 2
        Window.top = (Window.system_size[1] - 700) / 2


# --- Main App ---

class TexterApp(App):
    def build(self):
        self.title = 'Texter E2EE'
        self.controller = AppController()
        self.current_partner = None

        self.sm = ScreenManager()
        self.sm.add_widget(LoginScreen(name='login'))
        self.sm.add_widget(ChatScreen(name='chat'))
        return self.sm

    def on_start(self):
        self.controller.run()

    def on_stop(self):
        self.controller.network.shutdown()

    def enable_login_buttons(self):
        screen = self.sm.get_screen('login')
        screen.ids.login_btn.disabled = False
        screen.ids.register_btn.disabled = False

    def set_status(self, text, type="info"):
        try:
            current_screen = self.sm.current_screen
            if hasattr(current_screen.ids, 'status_label'):
                lbl = current_screen.ids.status_label
                lbl.text = text
                if type == "error":
                    lbl.color = (0.9, 0.3, 0.3, 1)
                elif type == "success":
                    lbl.color = (0.3, 0.8, 0.6, 1)
                else:
                    lbl.color = (0.6, 0.6, 0.6, 1)
        except:
            pass

    def switch_to_chat(self):
        self.sm.current = 'chat'
        self.set_status(f"Connected as {self.controller.username}", "success")

    def switch_to_login(self):
        self.sm.current = 'login'
        self.current_partner = None

    def add_contact(self, username):
        if not username: return
        chat_screen = self.sm.get_screen('chat')

        # FIX: Access contact_list directly from chat_screen.ids
        # Because the screen was defined inline in KV, the ID belongs to ChatScreen
        if 'contact_list' in chat_screen.ids:
            contact_list = chat_screen.ids.contact_list
            # Re-assign data to force update
            if not any(d['text'] == username for d in contact_list.data):
                new_data = contact_list.data + [{'text': username}]
                contact_list.data = new_data
        else:
            print("Error: contact_list ID not found in ChatScreen")

    def add_friend_request(self, username):
        if not username: return
        chat_screen = self.sm.get_screen('chat')

        # FIX: Access request_list directly from chat_screen.ids
        if 'request_list' in chat_screen.ids:
            request_list = chat_screen.ids.request_list
            if not any(d['username'] == username for d in request_list.data):
                new_data = request_list.data + [{'username': username}]
                request_list.data = new_data

    def remove_friend_request(self, username):
        chat_screen = self.sm.get_screen('chat')
        if 'request_list' in chat_screen.ids:
            request_list = chat_screen.ids.request_list
            request_list.data = [d for d in request_list.data if d['username'] != username]

    def select_partner(self, username):
        self.current_partner = username
        screen = self.sm.get_screen('chat')

        # Visual Update
        screen.ids.chat_header.text = f"Chatting with {username}"
        screen.ids.chat_history.clear_widgets()

        # Logic Update
        self.controller.handle_user_select(username)
        print(f"Partner selected: {username}")

    def send_message(self):
        screen = self.sm.get_screen('chat')
        text = screen.ids.message_input.text.strip()
        if text and self.current_partner:
            self.controller.send_message(self.current_partner, text)
            screen.ids.message_input.text = ""

    def add_message(self, sender, text):
        screen = self.sm.get_screen('chat')
        is_me = (sender == "Me" or sender == self.controller.username)
        history = screen.ids.chat_history
        scroll = screen.ids.chat_scroll

        lbl = MessageLabel(text=text, is_me=is_me)
        history.add_widget(lbl)

        # Scroll to bottom
        Clock.schedule_once(lambda dt: setattr(scroll, 'scroll_y', 0), 0.1)

    def load_chat_history(self, history, my_username):
        screen = self.sm.get_screen('chat')
        screen.ids.chat_history.clear_widgets()
        for item in history:
            sender = item['sender']
            msg = item['message']
            is_me = (sender == my_username)
            lbl = MessageLabel(text=msg, is_me=is_me)
            screen.ids.chat_history.add_widget(lbl)

        Clock.schedule_once(lambda dt: setattr(screen.ids.chat_scroll, 'scroll_y', 0), 0.1)

    def dev_clear_databases(self):
        import os
        data_dir = self.user_data_dir
        if os.path.exists(data_dir):
            for filename in os.listdir(data_dir):
                if filename.endswith(".db") or filename.endswith(".db-journal"):
                    try:
                        os.remove(os.path.join(data_dir, filename))
                    except:
                        pass
            self.set_status("Databases cleared", "info")


if __name__ == '__main__':
    TexterApp().run()