import flet as ft
from services.app_controller import AppController
import json
import traceback
import sys
from typing import cast

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
    status_text = ft.Text(value="Initializing...", size=12, color=COLORS["text_secondary"],
                          text_align=ft.TextAlign.CENTER)

    login_btn = ft.Button("Login", width=140, bgcolor=COLORS["accent"], color="white", disabled=True)
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

    def _apply_status_update(text, level="info"):
        status_text.value = text
        if level == "error":
            status_text.color = ft.Colors.RED_400
        elif level == "success":
            status_text.color = COLORS["accent"]
        else:
            status_text.color = COLORS["text_secondary"]
        try:
            page.update()
        except:
            pass

    async def _schedule_status_update(text, level="info"):
        _apply_status_update(text, level)

    def handle_status(text, level="info"):
        try:
            page.run_task(_schedule_status_update, text, level)
        except Exception:
            _apply_status_update(text, level)

    def select_partner(username):
        if not controller:
            handle_status("App not initialized", "error")
            return
        current_chat_name.value = username
        controller.handle_user_select(username)
        navigate_to_route("/chat_detail")

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
            padding=12,
            ink=True,
            on_click=lambda e: select_partner(username),
            data=username,
            border=ft.Border(bottom=ft.BorderSide(1, "#202c33"))
        )

    def add_message_bubble(text, is_me, update=True):
        bubble_color = COLORS["bubble_self"] if is_me else COLORS["bubble_other"]
        alignment = ft.MainAxisAlignment.END if is_me else ft.MainAxisAlignment.START
        radius = ft.BorderRadius(top_left=10, top_right=10, bottom_left=10 if is_me else 0,
                                  bottom_right=0 if is_me else 10)

        chat_history.controls.append(
            ft.Row([
                ft.Container(
                    content=ft.Column([
                        ft.Text(text, color=COLORS["text_primary"], size=15, selectable=True),
                    ], spacing=0),
                    padding=8,
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

    async def _push_route(route):
        await page.push_route(route)

    def navigate_to_route(route):
        try:
            page.run_task(_push_route, route)
        except Exception:
            try:
                page.route = route
                route_change(route)
            except:
                pass

    # --- UI Update Handler ---

    def _apply_ui_update(action, data=None):
        if action == "ENABLE_LOGIN":
            login_btn.disabled = False
            register_btn.disabled = False
            try:
                page.update()
            except:
                pass

        elif action == "SWITCH_TO_CHAT":
            navigate_to_route("/home")

        elif action == "SWITCH_TO_LOGIN":
            navigate_to_route("/login")

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
                            ft.Text(str(data) if data else "", expand=True, color=COLORS["text_primary"], size=16),
                        ]),
                        ft.Button("Accept",
                                  on_click=lambda e, u=data: (controller.accept_friend_request(u) if controller else handle_status("App not ready", "error")),
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
                            ft.Text(str(data) if data else "", expand=True, color=COLORS["text_primary"], size=16),
                        ]),
                        ft.Container(
                            content=ft.Text("Pending", size=12, color=ft.Colors.YELLOW_600),
                            padding=4,
                            border=ft.Border(left=ft.BorderSide(1, ft.Colors.YELLOW_600), right=ft.BorderSide(1, ft.Colors.YELLOW_600), top=ft.BorderSide(1, ft.Colors.YELLOW_600), bottom=ft.BorderSide(1, ft.Colors.YELLOW_600)),
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
            if data:
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
            if data:
                sender, text = data
                is_me = (sender == "Me" or (controller and sender == controller.username))
                add_message_bubble(text, is_me, update=True)

    async def _schedule_ui_update(action, data=None):
        _apply_ui_update(action, data)

    def handle_ui_update(action, data=None):
        try:
            page.run_task(_schedule_ui_update, action, data)
        except Exception:
            _apply_ui_update(action, data)

    def send_msg_click(e):
        if message_input.value and controller:
            try:
                controller.send_message(message_input.value)
                message_input.value = ""
                try:
                    page.update()
                except:
                    pass
            except Exception as ex:
                handle_status(f"Send error: {str(ex)}", "error")
                print(traceback.format_exc(), file=sys.stderr)
        elif not controller:
            handle_status("App not ready", "error")

    # --- Initialize Controller with Error Handling ---
    controller = None
    try:
        controller = AppController(page, handle_ui_update, handle_status)
    except Exception as e:
        error_msg = f"Failed to initialize app: {str(e)}"
        print(f"ERROR: {error_msg}\n{traceback.format_exc()}", file=sys.stderr)
        status_text.value = error_msg
        status_text.color = ft.Colors.RED_400

    # Safe wrappers for controller methods
    def safe_login(e):
        if controller:
            try:
                controller.handle_login_request(user_input.value, pass_input.value)
            except Exception as ex:
                handle_status(f"Login error: {str(ex)}", "error")
                print(traceback.format_exc(), file=sys.stderr)
        else:
            handle_status("App not ready", "error")

    def safe_register(e):
        if controller:
            try:
                controller.handle_register_request(user_input.value, pass_input.value)
            except Exception as ex:
                handle_status(f"Register error: {str(ex)}", "error")
                print(traceback.format_exc(), file=sys.stderr)
        else:
            handle_status("App not ready", "error")

    login_btn.on_click = safe_login
    register_btn.on_click = safe_register

    # --- Tab Change Handler ---
    def on_tab_change(e):
        if controller and e.control.selected_index == 1:  # Requests tab
            try:
                controller.network.send_payload(json.dumps({"command": "get_pending_friend_requests"}))
            except Exception as ex:
                print(f"Tab change error: {ex}", file=sys.stderr)
        page.update()

    def safe_refresh_contacts(e):
        if controller:
            try:
                controller.network.send_payload(json.dumps({"command": "get_pending_friend_requests"}))
            except Exception as ex:
                print(f"Refresh contacts error: {ex}", file=sys.stderr)

    def safe_send_friend_request(e):
        if controller:
            try:
                controller.send_friend_request(req_input.value)
            except Exception as ex:
                handle_status(f"Request error: {str(ex)}", "error")
                print(traceback.format_exc(), file=sys.stderr)
        else:
            handle_status("App not ready", "error")

    def safe_logout(e):
        if controller:
            try:
                controller.logout()
            except Exception as ex:
                print(f"Logout error: {ex}", file=sys.stderr)

    # --- Route / View Management ---

    def route_change(route):
        page.views.clear()

        # --- VIEW 1: LOGIN ---
        if page.route == "/login":
            page.views.append(
                ft.View(
                    route="/login",
                    controls=[
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
                            alignment=ft.Alignment.CENTER,
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
                            on_click=safe_refresh_contacts
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
                                      on_click=safe_send_friend_request),
                        ft.IconButton(
                            ft.Icons.REFRESH,
                            icon_color=COLORS["accent"],
                            tooltip="Refresh Requests",
                            on_click=safe_refresh_contacts
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

            tab_bar = ft.TabBar(
                tabs=[
                    ft.Tab(label="CHATS"),
                    ft.Tab(label="REQUESTS"),
                ],
                scrollable=False,
            )
            tab_view = ft.TabBarView(
                expand=True,
                controls=[
                    chats_tab,
                    requests_tab,
                ],
            )
            tabs = ft.Tabs(
                length=2,
                selected_index=0,
                animation_duration=300,
                expand=True,
                content=ft.Column(
                    expand=True,
                    controls=cast(list[ft.Control], [tab_bar, tab_view]),
                ),
                on_change=on_tab_change,
            )

            page.views.append(
                ft.View(
                    route="/home",
                    controls=[
                        ft.AppBar(
                            title=ft.Text("Texter", weight=ft.FontWeight.BOLD),
                            bgcolor=COLORS["appbar"],
                            color=COLORS["text_secondary"],
                            actions=[
                                ft.IconButton(ft.Icons.SEARCH, icon_color=COLORS["text_secondary"]),
                                ft.IconButton(ft.Icons.LOGOUT, icon_color=COLORS["text_secondary"],
                                              on_click=safe_logout)
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
                    route="/chat_detail",
                    controls=[
                        ft.AppBar(
                            leading=ft.IconButton(ft.Icons.ARROW_BACK, on_click=lambda _: navigate_to_route("/home")),
                            leading_width=40,
                            title=ft.Row([
                                ft.CircleAvatar(content=ft.Text(current_chat_name.value[:1].upper()), radius=18,
                                                bgcolor=COLORS["accent"]),
                                ft.Text(current_chat_name.value, size=18, weight=ft.FontWeight.NORMAL)
                            ]),
                            bgcolor=COLORS["appbar"],
                            actions=[
                                # Feature not implemented yet
                            ]
                        ),
                        ft.Stack(
                            [
                                ft.Image(
                                    src="https://user-images.githubusercontent.com/15075759/28719144-86dc0f70-73b1-11e7-911d-60d70fcded21.png",
                                    fit="cover",  # type: ignore
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
        
        else:
            # Fallback to login screen if no route matches
            page.views.append(
                ft.View(
                    route="/login",
                    controls=[
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
                            alignment=ft.Alignment.CENTER,
                            expand=True,
                            padding=40,
                            bgcolor=COLORS["bg"]
                        )
                    ],
                    bgcolor=COLORS["bg"],
                    padding=0
                )
            )

        page.update()

    def view_pop(view):
        if page.views:
            page.views.pop()
        if page.views:
            top_view = page.views[-1]
            navigate_to_route(top_view.route)
        else:
            navigate_to_route("/login")

    def lifecycle_change(e):
        if controller:
            try:
                controller.handle_lifecycle_change(e.data)
            except Exception as ex:
                print(f"Lifecycle change error: {ex}", file=sys.stderr)

    # Set route handler BEFORE navigating
    page.on_route_change = route_change
    page.on_view_pop = view_pop
    page.on_app_lifecycle_state_change = lifecycle_change

    # Initial route setup with fallback
    try:
        # Manually trigger route_change to ensure login screen appears
        page.route = "/login"
        route_change("/login")
        
        if controller:
            controller.run()
        else:
            status_text.value = "Failed to initialize application"
            status_text.color = ft.Colors.RED_400
            page.update()
    except Exception as e:
        error_msg = f"Startup Error: {str(e)}\n{traceback.format_exc()}"
        print(error_msg, file=sys.stderr)
        status_text.value = error_msg
        status_text.color = ft.Colors.RED_400
        try:
            page.update()
        except:
            pass


if __name__ == "__main__":
    try:
        ft.run(main)
    except Exception as e:
        print(f"Fatal Error: {str(e)}", file=sys.stderr)
        print(traceback.format_exc(), file=sys.stderr)