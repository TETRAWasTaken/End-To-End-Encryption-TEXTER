import socket
import sys
import threading
import re
import Socket as S
import cache_managment_system as CMS

ACTIVEUSERS = {}

class Server(socket.socket):
    def __init__(self):
        super().__init__(socket.AF_INET6, socket.SOCK_STREAM)
        global ACTIVEUSERS
        self.secondary_event_initiator()
        self.users = []
        self.server_initiator()

    def server_initiator(self):
        self.cms = CMS.CACHEManager_Handler()
        self.credentials = self.cms.credentials
        print("Cache Management and Handler system activated")
        utc_Thread = threading.Thread(target=self.user_thread_checker)
        utc_Thread.start()
        self.PNS()

    def PNS(self):
        self.PNS_socket = socket.socket(socket.AF_INET6, socket.SOCK_STREAM, 0)
        self.PNS_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.PNS_socket.bind((self.host, 12345, 0, 0))
        self.PNS_socket.listen(5)
        print("PNS activated on port 12345")
        n = 0
        while True:
            try:
                self.PNSclient_scoket, addr = self.PNS_socket.accept()
                print(f"Connection from {addr} has been established, waiting for login or registration")

                # Create a thread to handle this client
                client_thread = threading.Thread(target=self.handle_client_auth, args=(self.PNSclient_scoket, addr, n))
                client_thread.daemon = True
                client_thread.start()

                # Increment port counter for next client
                if n < len(self.ports) - 1:
                    n += 1
                else:
                    n = 0  # Reset back to the first port if we've used them all

            except Exception as e:
                print(f"Error in PNS server: {e}")
                continue

    def handle_client_auth(self, client_socket, addr, port_index):
        try:
            # Receive login or registration command
            logorreg = client_socket.recv(2048).decode()

            if (logorreg == 'login'):
                print(f"Login requested by {addr}")
                cred = client_socket.recv(2048).decode()
                user = re.search("(^.*?#)", cred)
                passw = re.search("[^#]*$", cred)

                if not user or not passw:
                    print(f"Invalid credential format from {addr}")
                    client_socket.send(("Invalid format").encode())
                    return

                try:
                    if (self.credentials[user.group(0)] == passw.group(0)):
                        # Successful login
                        yes = '1'
                        client_socket.sendall(yes.encode())

                        # Wait for port request
                        req = client_socket.recv(2048).decode()
                        if req and req == 'sendport':
                            # Send port for chat server
                            Socket = S.Server(port = self.ports[port_index], cms = self.cms)
                            thread = threading.Thread(target=Socket.start)
                            thread.start()
                            client_socket.send(str(self.ports[port_index]).encode())
                            self.users.append(user.group(0))
                            ACTIVEUSERS[user.group(0)] = thread
                            print(f"User {user.group(0)} logged in and assigned port {self.ports[port_index]}")

                    elif (self.credentials[user.group(0)] != passw.group(0)):
                        print(f"self.credentials don't match for client {addr}")
                        client_socket.send(("Credfail").encode())

                except (KeyError):
                    print(f"Account not found for {user.group(0) if user else 'unknown'}")
                    client_socket.send(("NAF").encode())

            elif (logorreg == 'reg'):
                print(f"Registration requested by {addr}")
                cred = client_socket.recv(2048).decode()
                user = re.search("(^.*?#)", cred)
                passw = re.search("[^#]*$", cred)

                if not user or not passw:
                    print(f"Invalid registration format from {addr}")
                    client_socket.send(("Invalid format").encode())
                    return

                if user.group(0) in self.credentials.keys():
                    print(f"Registration failed, username {user.group(0)} already exists")
                    client_socket.send(('AAE').encode())
                else:
                    print(f"Registration successful for {user.group(0)} from {addr}")
                    self.credentials[user.group(0)] = passw.group(0)
                    print(f"Updated self.credentials: {self.credentials}")
                    client_socket.send(('success').encode())
                    for username in self.credentials.keys():
                        username = username.strip('#')  # Remove # from username for cache key
                    self.cms.update_Credentials()

            else:
                print(f"Unknown command '{logorreg}' from {addr}")
                client_socket.send(("Unknown command").encode())

        except Exception as e:
            print(f"Error handling client {addr}: {e}")
        finally:
            try:
                client_socket.close()
            except:
                pass

    def user_thread_checker(self):
        while True:
            try:
                for i in ACTIVEUSERS:
                    if ACTIVEUSERS[i].is_alive() == False:
                        ACTIVEUSERS[i].join()
                        self.cms.del_user_Match(i)
                        del ACTIVEUSERS[i]
                        print(f"User {i} disconnected")
                    else:
                        continue
                self.cms.ACTIVEUSERS = ACTIVEUSERS
            except:
                continue

    def secondary_event_initiator(self):
        hostname = socket.gethostname()
        self.addresses = socket.getaddrinfo(hostname, None, socket.AF_INET6)
        self.host = self.addresses[0][4][0]
        self.ports = list(range(12346, 12351))



if __name__ == "__main__":
    try:
        Server()
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)
