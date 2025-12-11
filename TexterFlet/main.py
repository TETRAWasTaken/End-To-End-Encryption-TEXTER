import flet as ft
from services.app_controller import AppController
import json
import threading


def main(page: ft.Page):
    page.title = "Texter E2EE"
    page.theme_mode = ft.ThemeMode.DARK
    page.window.width = 400
    page.window.height = 700
    page.padding = 0

    # --- UI Controls ---
    user_input = ft.TextField(label="Username", width=280)
    pass_input = ft.TextField(label="Password", password=True, can_reveal_password=True, width=280)
    status_text = ft.Text(value="Ready to connect", size=12, color=ft.Colors.GREY)

    login_btn = ft.ElevatedButton("Login", width=130, disabled=True)
    register_btn = ft.ElevatedButton("Register", width=130, disabled=True)

    contacts_view = ft.ListView(expand=True, spacing=5)
    requests_view = ft.ListView(expand=True, spacing=5)

    chat_history = ft.ListView(expand=True, spacing=10, auto_scroll=True, padding=10)
    message_input = ft.TextField(hint_text="Type a message...", expand=True, bgcolor=ft.Colors.GREY_900)
    chat_header_text = ft.Text("Select a contact", size=16, weight=ft.FontWeight.BOLD)

    new_contact_input = ft.TextField(hint_text="Username", width=150, height=40, content_padding=10)
    req_input = ft.TextField(hint_text="Username", width=150, height=40, content_padding=10)

    # --- Logic ---

    def handle_status(text, type="info"):
        def update():
            status_text.value = text
            if type == "error":
                status_text.color = ft.Colors.RED
            elif type == "success":
                status_text.color = ft.Colors.GREEN
            else:
                status_text.color = ft.Colors.GREY
            page.update()

        if threading.current_thread() != threading.main_thread():
            pass
        update()

    def handle_ui_update(action, data=None):
        if action == "ENABLE_LOGIN":
            login_btn.disabled = False
            register_btn.disabled = False

        elif action == "SWITCH_TO_CHAT":
            page.go("/chat")

        elif action == "SWITCH_TO_LOGIN":
            page.go("/login")

        elif action == "ADD_CONTACT":
            exists = any(c.data == data for c in contacts_view.controls)
            if not exists:
                btn = ft.Container(
                    content=ft.Row([
                        ft.Icon(ft.Icons.PERSON, color=ft.Colors.WHITE),
                        ft.Text(data, color=ft.Colors.WHITE, size=16)
                    ]),
                    padding=15,
                    border_radius=5,
                    bgcolor=ft.Colors.BLUE_GREY_900,
                    on_click=lambda e: select_partner(e.control.data),
                    data=data,
                    ink=True
                )
                contacts_view.controls.append(btn)

        elif action == "ADD_REQUEST":
            exists = any(c.data == data for c in requests_view.controls)
            if not exists:
                row = ft.Container(
                    content=ft.Row([
                        ft.Text(data, expand=True, color=ft.Colors.WHITE),
                        ft.ElevatedButton("Accept",
                                          on_click=lambda e: controller.accept_friend_request(data),
                                          bgcolor=ft.Colors.GREEN, color=ft.Colors.WHITE
                                          )
                    ]),
                    padding=10,
                    bgcolor=ft.Colors.GREY_800,
                    border_radius=5,
                    data=data
                )
                requests_view.controls.append(row)

        elif action == "REMOVE_REQUEST":
            requests_view.controls = [c for c in requests_view.controls if c.data != data]

        elif action == "LOAD_HISTORY":
            history, my_username = data
            chat_history.controls.clear()
            for item in history:
                sender = item['sender']
                msg = item['message']
                is_me = (sender == my_username)
                add_message_bubble(msg, is_me, update=False)

        elif action == "ADD_MESSAGE":
            sender, text = data
            is_me = (sender == "Me" or sender == controller.username)
            add_message_bubble(text, is_me, update=False)

        try:
            page.update()
        except:
            pass

    def add_message_bubble(text, is_me, update=True):
        chat_history.controls.append(
            ft.Row(
                [
                    # FIX: Simplified container with fixed width to prevent errors
                    ft.Container(
                        content=ft.Text(text, color=ft.Colors.WHITE, selectable=True),
                        padding=12,
                        width=260,  # Fixed width to ensure wrapping works without BoxConstraints
                        border_radius=ft.border_radius.only(
                            top_left=12, top_right=12,
                            bottom_left=0 if is_me else 12,
                            bottom_right=12 if is_me else 0
                        ),
                        bgcolor=ft.Colors.BLUE_700 if is_me else ft.Colors.GREY_800
                    )
                ],
                alignment=ft.MainAxisAlignment.END if is_me else ft.MainAxisAlignment.START
            )
        )
        if update:
            page.update()

    def select_partner(username):
        chat_header_text.value = f"Chatting with {username}"
        controller.handle_user_select(username)
        page.update()

    def send_msg_click(e):
        if message_input.value:
            controller.send_message(message_input.value)
            message_input.value = ""
            message_input.focus()
            page.update()

    controller = AppController(handle_ui_update, handle_status)

    login_btn.on_click = lambda e: controller.handle_login_request(user_input.value, pass_input.value)
    register_btn.on_click = lambda e: controller.handle_register_request(user_input.value, pass_input.value)

    def route_change(route):
        page.views.clear()

        # LOGIN SCREEN
        page.views.append(
            ft.View(
                "/login",
                [
                    ft.Container(
                        content=ft.Column(
                            [
                                ft.Text("TEXTER", size=40, weight=ft.FontWeight.BOLD, color=ft.Colors.GREEN),
                                ft.Text("Secure Encrypted Messenger", color=ft.Colors.GREY),
                                ft.Divider(height=40, color=ft.Colors.TRANSPARENT),
                                user_input,
                                pass_input,
                                ft.Divider(height=10, color=ft.Colors.TRANSPARENT),
                                ft.Row([login_btn, register_btn], alignment=ft.MainAxisAlignment.CENTER),
                                ft.Divider(height=20, color=ft.Colors.TRANSPARENT),
                                status_text
                            ],
                            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                            alignment=ft.MainAxisAlignment.CENTER
                        ),
                        alignment=ft.alignment.center,
                        expand=True,
                        padding=20
                    )
                ],
                bgcolor="#1e1e1e"
            )
        )

        # CHAT SCREEN
        if page.route == "/chat":
            chat_tabs = ft.Tabs(
                selected_index=0,
                animation_duration=300,
                expand=True,
                tabs=[
                    ft.Tab(
                        text="Contacts",
                        content=ft.Column([
                            ft.Container(
                                content=ft.Row([
                                    new_contact_input,
                                    ft.IconButton(ft.Icons.ADD, on_click=lambda e: controller.network.send_payload(
                                        json.dumps({"command": "get_pending_friend_requests"})))
                                ]),
                                padding=10
                            ),
                            contacts_view
                        ])
                    ),
                    ft.Tab(
                        text="Requests",
                        content=ft.Column([
                            ft.Container(
                                content=ft.Row([
                                    req_input,
                                    ft.IconButton(ft.Icons.SEND,
                                                  on_click=lambda e: controller.send_friend_request(req_input.value))
                                ]),
                                padding=10
                            ),
                            requests_view
                        ])
                    ),
                    ft.Tab(
                        text="Chat",
                        content=ft.Column([
                            ft.Container(
                                content=chat_header_text,
                                padding=15,
                                bgcolor=ft.Colors.BLACK26
                            ),
                            chat_history,
                            ft.Container(
                                content=ft.Row([
                                    message_input,
                                    ft.IconButton(ft.Icons.SEND, on_click=send_msg_click, icon_color=ft.Colors.BLUE)
                                ]),
                                padding=10,
                                bgcolor=ft.Colors.BLACK26
                            )
                        ])
                    )
                ]
            )

            page.views.append(
                ft.View(
                    "/chat",
                    [
                        ft.AppBar(
                            title=ft.Text("Texter E2EE"),
                            bgcolor=ft.Colors.BLUE_GREY_900,
                            actions=[
                                ft.IconButton(ft.Icons.LOGOUT, on_click=lambda e: controller.logout())
                            ]
                        ),
                        chat_tabs
                    ],
                    bgcolor="#1e1e1e",
                    padding=0
                )
            )

        page.update()

    def view_pop(view):
        page.views.pop()
        top_view = page.views[-1]
        page.go(top_view.route)

    page.on_route_change = route_change
    page.on_view_pop = view_pop

    page.go("/login")
    controller.run()


ft.app(target=main)