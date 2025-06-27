import queue
import socket
import threading
import time
from typing import Optional, Callable
import cache_managment_system as CMS

hostname = socket.gethostname()
addresses = socket.getaddrinfo(hostname, None, socket.AF_INET6)
ipv6_address = addresses[0][4][0]

class Server(socket.socket):
    def __init__(self, host=ipv6_address, port = None, cms: CMS.CACHEManager_Handler = None):
        super().__init__(socket.AF_INET6, socket.SOCK_STREAM)
        self.host = host
        self.port = port
        self.cms = cms
        self.command_queue = queue.Queue()

        if self.port is None or self.cms is None:
            quit()

    def _process_command(self):
        while not self.command_queue.empty():
            try:
                command_payload = self.command_queue.get_nowait()
                method_name = command_payload.get("method")
                args = command_payload.get("args", ())

                if method_name:
                    target_method = Optional[Callable] = getattr(self, method_name, None)
                    if target_method and callable(target_method):
                        target_method(args[0])
                    else:
                        continue
                self.command_queue.task_done()

            except queue.Empty:
                pass
            except:
                pass

    def start(self):
        print(f"Initiating socket instance on port : {self.port}")
        socket_Thread = threading.Thread(target=self.socket)
        socket_Thread.start()

    def socket(self):
        self.servernames = []
        self.server_socket = socket.socket(socket.AF_INET6, socket.SOCK_STREAM, 0)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port, 0, 0))
        self.server_socket.listen(5)

        while True:
            self.client_socket, addr = self.server_socket.accept()
            print(f"Connection from {addr} has been established on Port {self.port}.")
            user2 = self.client_socket.recv(2048).decode()
            user1 = self.client_socket.recv(2048).decode()
            self.servernames.append(user1)
            self.servernames.append(user2)
            t1 = threading.Thread(target=self.processing)
            t1.start()

    def processing(self):
        user = self.servernames[0]
        user2 = self.servernames[1]
        self.cms.user_Match(user, user2)
        t3 = threading.Thread(target=self.prompt)
        t6 = threading.Thread(target=self.tcachepromt, args=(user, user2))
        t7 = threading.Thread(target=self._process_command)
        t3.start()
        t6.start()
        t7.start()
        t3.join()
        t6.join()
        t7.join()

    def prompt(self):
        user = self.servernames[0]
        user2 = self.servernames[1]
        while True:
            try:
                received_data = self.client_socket.recv(2048).decode()
                if not received_data:
                    break
                if self.cms.online_Status(user2, user):
                    self.cms.updateCache(user,user2,received_data,1)
                    self.cms.send_Text(user2, received_data)
                    self.cms.update_CACHE()
                else:
                    self.cms.updateCache(user,user2,received_data,0)
                    self.cms.update_CACHE()
            except (ConnectionError, ConnectionAbortedError):
                print(f"Connection closed by {user}")
                quit()

    def tcachepromt(self, user, user2):
        self.tcache = self.cms.getCache(user2, user)
        while True:
            try:
                for i in self.tcache.keys():
                    if self.tcache[i][2]==user2:
                        if self.tcache[i][1] == 0:
                            time.sleep(0.1)
                            try:
                                self.client_socket.send(self.tcache[i][0].encode())
                            except (AttributeError):
                                continue
                            self.tcache[i][1] = 1
                        else:
                            continue
                    else:
                        continue
            except (ConnectionRefusedError, ConnectionError, RuntimeError):
                continue

    def cmspromt(self, text):
        try:
            self.client_socket.send(text.encode())
        except (ConnectionError, ConnectionAbortedError):
            pass






