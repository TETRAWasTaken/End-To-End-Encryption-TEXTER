import flet as ft
from services.app_controller import AppController
import json
import threading

# --- WhatsApp-like Color Palette (Dark Mode) ---
COLORS = {
    "bg": "#111b21",  # Main Background
    "appbar": "#202c33",  # Top Bar / Sidebar
    "card": "#202c33",  # Elements / Input
    "text_primary": "#e9edef",
    "text_secondary": "#8696a0",
    "accent": "#00a884",  # WhatsApp Green
    "bubble_self": "#005c4b",  # My Message
    "bubble_other": "#202c33",  # Their Message
    "input_bg": "#2a3942",
}


def main(page: ft.Page):
    page.title = "Texter E2EE"
    page.theme_mode = ft.ThemeMode.DARK
    page.bgcolor = COLORS["bg"]

    # Mobile-first dimensions
    page.window.width = 400
    page.window.height = 750
    page.padding = 0

    # --- Persistent UI Controls ---

    # LOGIN CONTROLS
    user_input = ft.TextField(label="Username", bgcolor=COLORS["input_bg"], border_color=COLORS["input_bg"],
                              color=COLORS["text_primary"], border_radius=20, prefix_icon=ft.Icons.PERSON)
    pass_input = ft.TextField(label="Password", password=True, can_reveal_password=True, bgcolor=COLORS["input_bg"],
                              border_color=COLORS["input_bg"], color=COLORS["text_primary"], border_radius=20,
                              prefix_icon=ft.Icons.LOCK)
    status_text = ft.Text(value="Ready to connect", size=12, color=COLORS["text_secondary"],
                          text_align=ft.TextAlign.CENTER)

    login_btn = ft.ElevatedButton("Login", width=140, bgcolor=COLORS["accent"], color="white", disabled=True)
    register_btn = ft.OutlinedButton("Register", width=140, style=ft.ButtonStyle(color=COLORS["accent"]), disabled=True)

    # HOME CONTROLS (Lists)
    contacts_view = ft.ListView(expand=True, spacing=0, padding=0)
    requests_view = ft.ListView(expand=True, spacing=10, padding=20)
    sent_requests_view = ft.ListView(expand=True, spacing=10, padding=20)  # NEW: Sent requests list

    new_contact_input = ft.TextField(hint_text="Add contact by username", bgcolor=COLORS["input_bg"], border_radius=20,
                                     border_width=0, height=45, content_padding=15, expand=True,
                                     text_style=ft.TextStyle(color=COLORS["text_primary"]))
    req_input = ft.TextField(hint_text="Send request to...", bgcolor=COLORS["input_bg"], border_radius=20,
                             border_width=0, height=45, content_padding=15, expand=True)

    # CHAT CONTROLS
    chat_history = ft.ListView(expand=True, spacing=4, padding=15, auto_scroll=True)
    message_input = ft.TextField(hint_text="Message", border_radius=25, bgcolor=COLORS["input_bg"], border_width=0,
                                 color=COLORS["text_primary"], multiline=True, min_lines=1, max_lines=5,
                                 content_padding=15, expand=True)

    current_chat_name = ft.Text("", size=18, weight=ft.FontWeight.BOLD, color=COLORS["text_primary"])

    # --- Logic Helpers ---

    def handle_status(text, type="info"):
        def update():
            status_text.value = text
            if type == "error":
                status_text.color = ft.Colors.RED_400
            elif type == "success":
                status_text.color = COLORS["accent"]
            else:
                status_text.color = COLORS["text_secondary"]
            try:
                page.update()
            except:
                pass

        if threading.current_thread() != threading.main_thread():
            pass
        update()

    def select_partner(username):
        current_chat_name.value = username
        controller.handle_user_select(username)
        page.go("/chat_detail")

    def build_contact_tile(username):
        return ft.Container(
            content=ft.Row([
                ft.CircleAvatar(bgcolor=COLORS["text_secondary"],
                                content=ft.Icon(ft.Icons.PERSON, color="white", size=20), radius=22),
                ft.Column([
                    ft.Text(username, size=16, weight=ft.FontWeight.BOLD, color=COLORS["text_primary"]),
                    ft.Text("Tap to chat", size=13, color=COLORS["text_secondary"])
                ], spacing=2, alignment=ft.MainAxisAlignment.CENTER),
            ], alignment=ft.MainAxisAlignment.START),
            padding=ft.padding.symmetric(vertical=12, horizontal=15),
            ink=True,
            on_click=lambda e: select_partner(username),
            data=username,
            border=ft.border.only(bottom=ft.BorderSide(1, "#202c33"))
        )

    def add_message_bubble(text, is_me, update=True):
        bubble_color = COLORS["bubble_self"] if is_me else COLORS["bubble_other"]
        alignment = ft.MainAxisAlignment.END if is_me else ft.MainAxisAlignment.START
        radius = ft.border_radius.only(top_left=10, top_right=10, bottom_left=10 if is_me else 0,
                                       bottom_right=0 if is_me else 10)

        chat_history.controls.append(
            ft.Row([
                ft.Container(
                    content=ft.Column([
                        ft.Text(text, color=COLORS["text_primary"], size=15, selectable=True),
                    ], spacing=0),
                    padding=ft.padding.symmetric(vertical=8, horizontal=12),
                    bgcolor=bubble_color,
                    border_radius=radius,
                    width=280,
                )
            ], alignment=alignment)
        )
        if update:
            try:
                chat_history.update()
            except:
                pass

    # --- UI Update Handler ---

    def handle_ui_update(action, data=None):
        if action == "ENABLE_LOGIN":
            login_btn.disabled = False
            register_btn.disabled = False
            try:
                page.update()
            except:
                pass

        elif action == "SWITCH_TO_CHAT":
            page.go("/home")

        elif action == "SWITCH_TO_LOGIN":
            page.go("/login")

        elif action == "ADD_CONTACT":
            exists = any(c.data == data for c in contacts_view.controls)
            if not exists:
                contacts_view.controls.append(build_contact_tile(data))
                try:
                    contacts_view.update()
                except:
                    pass
                try:
                    page.update()
                except:
                    pass

        elif action == "ADD_REQUEST":
            exists = any(c.data == data for c in requests_view.controls)
            if not exists:
                row = ft.Container(
                    content=ft.Row([
                        ft.Row([
                            ft.Icon(ft.Icons.PERSON_ADD, color=COLORS["accent"]),
                            ft.Text(data, expand=True, color=COLORS["text_primary"], size=16),
                        ]),
                        ft.ElevatedButton("Accept",
                                          on_click=lambda e: controller.accept_friend_request(data),
                                          bgcolor=COLORS["accent"], color="white",
                                          style=ft.ButtonStyle(shape=ft.RoundedRectangleBorder(radius=8))
                                          )
                    ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
                    padding=15,
                    bgcolor=COLORS["card"],
                    border_radius=10,
                    data=data
                )
                requests_view.controls.append(row)
                try:
                    requests_view.update()
                except:
                    pass
                try:
                    page.update()
                except:
                    pass

        elif action == "REMOVE_REQUEST":
            requests_view.controls = [c for c in requests_view.controls if c.data != data]
            try:
                requests_view.update()
            except:
                pass
            try:
                page.update()
            except:
                pass

        # --- NEW: Sent Request Handlers ---
        elif action == "ADD_SENT_REQUEST":
            exists = any(c.data == data for c in sent_requests_view.controls)
            if not exists:
                row = ft.Container(
                    content=ft.Row([
                        ft.Row([
                            ft.Icon(ft.Icons.OUTBOUND_OUTLINED, color=ft.Colors.GREY_400, size=20),
                            ft.Text(data, expand=True, color=COLORS["text_primary"], size=16),
                        ]),
                        ft.Container(
                            content=ft.Text("Pending", size=12, color=ft.Colors.YELLOW_600),
                            padding=ft.padding.symmetric(horizontal=8, vertical=4),
                            border=ft.border.all(1, ft.Colors.YELLOW_600),
                            border_radius=12
                        )
                    ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
                    padding=15,
                    bgcolor=COLORS["card"],
                    border_radius=10,
                    data=data
                )
                sent_requests_view.controls.append(row)
                try:
                    sent_requests_view.update()
                except:
                    pass
                try:
                    page.update()
                except:
                    pass

        elif action == "REMOVE_SENT_REQUEST":
            sent_requests_view.controls = [c for c in sent_requests_view.controls if c.data != data]
            try:
                sent_requests_view.update()
            except:
                pass
            try:
                page.update()
            except:
                pass
        # ----------------------------------

        elif action == "LOAD_HISTORY":
            history, my_username = data
            chat_history.controls.clear()
            for item in history:
                sender = item['sender']
                msg = item['message']
                is_me = (sender == my_username)
                add_message_bubble(msg, is_me, update=False)
            try:
                chat_history.update()
            except:
                pass

        elif action == "ADD_MESSAGE":
            sender, text = data
            is_me = (sender == "Me" or sender == controller.username)
            add_message_bubble(text, is_me, update=True)

    def send_msg_click(e):
        if message_input.value:
            controller.send_message(message_input.value)
            message_input.value = ""
            message_input.focus()
            try:
                page.update()
            except:
                pass

    # --- Initialize Controller ---
    controller = AppController(page, handle_ui_update, handle_status)

    login_btn.on_click = lambda e: controller.handle_login_request(user_input.value, pass_input.value)
    register_btn.on_click = lambda e: controller.handle_register_request(user_input.value, pass_input.value)

    # --- Tab Change Handler ---
    def on_tab_change(e):
        if e.control.selected_index == 1:  # Requests tab
            controller.network.send_payload(json.dumps({"command": "get_pending_friend_requests"}))
        page.update()

    # --- Route / View Management ---

    def route_change(route):
        page.views.clear()

        # --- VIEW 1: LOGIN ---
        if page.route == "/login":
            page.views.append(
                ft.View(
                    "/login",
                    [
                        ft.Container(
                            content=ft.Column(
                                [
                                    ft.Icon(ft.Icons.LOCK_OUTLINE, size=60, color=COLORS["accent"]),
                                    ft.Text("TEXTER", size=30, weight=ft.FontWeight.BOLD, color=COLORS["text_primary"]),
                                    ft.Text("End-to-End Encrypted", color=COLORS["text_secondary"]),
                                    ft.Divider(height=30, color="transparent"),
                                    user_input,
                                    pass_input,
                                    ft.Divider(height=10, color="transparent"),
                                    ft.Column([login_btn, register_btn], spacing=10),
                                    ft.Divider(height=20, color="transparent"),
                                    status_text
                                ],
                                horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                                alignment=ft.MainAxisAlignment.CENTER,
                            ),
                            alignment=ft.alignment.center,
                            expand=True,
                            padding=40,
                            bgcolor=COLORS["bg"]
                        )
                    ],
                    bgcolor=COLORS["bg"],
                    padding=0
                )
            )

        # --- VIEW 2: HOME (CHATS LIST) ---
        elif page.route == "/home":
            # Tab content
            chats_tab = ft.Column([
                ft.Container(
                    content=ft.Row([
                        new_contact_input,
                        ft.IconButton(
                            ft.Icons.REFRESH,
                            icon_color=COLORS["accent"],
                            tooltip="Refresh Contacts",
                            on_click=lambda e: controller.network.send_payload(
                                json.dumps({"command": "get_pending_friend_requests"}))
                        )
                    ]),
                    padding=10,
                    bgcolor=COLORS["bg"]
                ),
                contacts_view
            ], expand=True)

            # Updated Requests Tab Layout (FIXED)
            requests_tab = ft.Column([
                ft.Container(
                    content=ft.Row([
                        req_input,
                        ft.IconButton(ft.Icons.SEND_ROUNDED, icon_color=COLORS["accent"],
                                      on_click=lambda e: controller.send_friend_request(req_input.value)),
                        ft.IconButton(
                            ft.Icons.REFRESH,
                            icon_color=COLORS["accent"],
                            tooltip="Refresh Requests",
                            on_click=lambda e: controller.network.send_payload(
                                json.dumps({"command": "get_pending_friend_requests"}))
                        )
                    ]),
                    padding=10
                ),
                # Split view: Incoming vs Sent
                ft.Column([
                    ft.Text("INCOMING", size=12, color=COLORS["text_secondary"], weight=ft.FontWeight.BOLD),
                    ft.Container(content=requests_view, height=200),
                    ft.Divider(color=COLORS["appbar"]),
                    ft.Text("SENT (PENDING)", size=12, color=COLORS["text_secondary"], weight=ft.FontWeight.BOLD),
                    ft.Container(content=sent_requests_view, expand=True)
                ], expand=True, spacing=5, scroll=ft.ScrollMode.AUTO)
            ], expand=True, spacing=10)

            tabs = ft.Tabs(
                selected_index=0,
                animation_duration=300,
                indicator_color=COLORS["accent"],
                label_color=COLORS["accent"],
                unselected_label_color=COLORS["text_secondary"],
                divider_color="transparent",
                expand=True,
                on_change=on_tab_change,
                tabs=[
                    ft.Tab(text="CHATS", content=chats_tab),
                    ft.Tab(text="REQUESTS", content=requests_tab),
                ]
            )

            page.views.append(
                ft.View(
                    "/home",
                    [
                        ft.AppBar(
                            title=ft.Text("Texter", weight=ft.FontWeight.BOLD),
                            bgcolor=COLORS["appbar"],
                            color=COLORS["text_secondary"],
                            actions=[
                                ft.IconButton(ft.Icons.SEARCH, icon_color=COLORS["text_secondary"]),
                                ft.IconButton(ft.Icons.LOGOUT, icon_color=COLORS["text_secondary"],
                                              on_click=lambda e: controller.logout())
                            ]
                        ),
                        tabs
                    ],
                    bgcolor=COLORS["bg"],
                    padding=0,
                    spacing=0
                )
            )

        # --- VIEW 3: CHAT DETAIL ---
        elif page.route == "/chat_detail":
            page.views.append(
                ft.View(
                    "/chat_detail",
                    [
                        ft.AppBar(
                            leading=ft.IconButton(ft.Icons.ARROW_BACK, on_click=lambda _: page.go("/home")),
                            leading_width=40,
                            title=ft.Row([
                                ft.CircleAvatar(content=ft.Text(current_chat_name.value[:1].upper()), radius=18,
                                                bgcolor=COLORS["accent"]),
                                ft.Text(current_chat_name.value, size=18, weight=ft.FontWeight.NORMAL)
                            ]),
                            bgcolor=COLORS["appbar"],
                            actions=[
                                ft.IconButton(ft.Icons.VIDEO_CALL, icon_color=COLORS["text_primary"]),
                                ft.IconButton(ft.Icons.CALL, icon_color=COLORS["text_primary"]),
                                ft.PopupMenuButton(
                                    items=[ft.PopupMenuItem(text="View contact"), ft.PopupMenuItem(text="Clear chat")]
                                ),
                            ]
                        ),
                        ft.Stack(
                            [
                                ft.Image(
                                    src="https://user-images.githubusercontent.com/15075759/28719144-86dc0f70-73b1-11e7-911d-60d70fcded21.png",
                                    fit=ft.ImageFit.COVER,
                                    opacity=0.1,
                                    width=float("inf"),
                                    height=float("inf"),
                                    gapless_playback=True
                                ),
                                ft.Column([
                                    chat_history,
                                    ft.Container(
                                        content=ft.Row([
                                            ft.IconButton(ft.Icons.EMOJI_EMOTIONS_OUTLINED,
                                                          icon_color=COLORS["text_secondary"]),
                                            message_input,
                                            ft.IconButton(ft.Icons.MIC, icon_color=COLORS["text_secondary"]),
                                            ft.FloatingActionButton(
                                                icon=ft.Icons.SEND,
                                                bgcolor=COLORS["accent"],
                                                mini=True,
                                                on_click=send_msg_click
                                            )
                                        ], alignment=ft.MainAxisAlignment.CENTER),
                                        padding=10,
                                        bgcolor=COLORS["appbar"]
                                    )
                                ], expand=True)
                            ],
                            expand=True
                        )
                    ],
                    bgcolor=COLORS["bg"],
                    padding=0,
                    spacing=0
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