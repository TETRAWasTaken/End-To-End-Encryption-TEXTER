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
        hostname = socket.gethostname()
        self.addresses = socket.getaddrinfo(hostname, None, socket.AF_INET6)
        self.host = self.addresses[0][4][0]
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
        self.PNS_socket.bind((self.host, 443, 0, 0))
        self.PNS_socket.listen(5)
        print("PNS activated on port 443")
        while True:
            try:
                PNSclient_scoket, addr = self.PNS_socket.accept()
                print(f"Connection from {addr} has been established, waiting for login or registration")

                # Create a thread to handle this client
                client_thread = threading.Thread(target=self.handle_client_auth, args=(PNSclient_scoket, addr))
                client_thread.daemon = True
                client_thread.start()

            except Exception as e:
                print(f"Error in PNS server: {e}")
                continue

    def handle_client_auth(self, client_socket, addr):
        authenticated_and_handled = False
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

                        socket_handler = S.Server(client_socket=client_socket, cms=self.cms)
                        thread = threading.Thread(target=socket_handler.start)
                        thread.daemon = True
                        thread.start()

                        self.users.append(user.group(0))
                        ACTIVEUSERS[user.group(0)] = thread
                        print(f"User {user.group(0)} logged in and handed over to socket handler.")
                        authenticated_and_handled = True

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
            if not authenticated_and_handled:
                try:
                    client_socket.close()
                except:
                    pass

    def user_thread_checker(self):
        while True:
            try:
                for i in list(ACTIVEUSERS.keys()):
                    if not ACTIVEUSERS[i].is_alive():
                        ACTIVEUSERS[i].join()
                        self.cms.del_user_Match(i)
                        del ACTIVEUSERS[i]
                        print(f"User {i} disconnected")
                    else:
                        continue
                self.cms.ACTIVEUSERS = ACTIVEUSERS
            except (RuntimeError, KeyError):
                continue


if __name__ == "__main__":
    try:
        Server()
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)
