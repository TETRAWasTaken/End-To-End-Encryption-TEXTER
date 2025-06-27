import queue
import socket
import threading
import time
from typing import Optional, Callable
import cache_managment_system as CMS


class Server:
    def __init__(self, client_socket, cms: CMS.CACHEManager_Handler = None):
        self.client_socket = client_socket
        self.cms = cms
        self.command_queue = queue.Queue()
        self.servernames = []
        if self.cms is None:
            quit()

    def _process_command(self):
        while not self.command_queue.empty():
            try:
                command_payload = self.command_queue.get_nowait()
                method_name = command_payload.get("method")
                args = command_payload.get("args", ())

                if method_name:
                    target_method: Optional[Callable] = getattr(self, method_name, None)
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
        print(f"Handing over client socket to socket instance")
        self.handle_client()


    def handle_client(self):
        try:
            user2 = self.client_socket.recv(2048).decode()
            user1 = self.client_socket.recv(2048).decode()
            self.servernames.append(user1)
            self.servernames.append(user2)
            self.processing()
        except Exception as e:
            print(f"Error handling client in Socket.Server: {e}")
            self.client_socket.close()

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
        self.client_socket.close()
        print(f"Closed connection for {user}")


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
                break

    def tcachepromt(self, user, user2):
        self.tcache = self.cms.getCache(user2, user)
        if not self.tcache:
            print(f"An Unknown error occured while fetching cache for {user2} from {user}")
        else:
            while True:
                try:
                    if self.client_socket._closed:
                        break
                    for i in self.tcache.keys():
                        if self.tcache[i][2] == user2:
                            if self.tcache[i][1] == 0:
                                time.sleep(0.1)
                                try:
                                    self.client_socket.send(self.tcache[i][0].encode())
                                except (AttributeError, ConnectionError):
                                    continue
                                self.tcache[i][1] = 1
                            else:
                                continue
                        else:
                            continue
                    time.sleep(0.5)
                except (ConnectionRefusedError, ConnectionError, RuntimeError):
                    break

    def cmspromt(self, text):
        try:
            self.client_socket.send(text.encode())
        except (ConnectionError, ConnectionAbortedError):
            pass