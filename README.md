# End-to-End-Encryption-Messaging-Aplication
**Important Note:**

This application is still in development. As the sole developer working on the project, it will take a significant amount of time and additional commits to complete.

**End-to-End Encryption:**
End-to-end encryption will be added in later commits. Currently, the encryption is rudimentary and not suitable for use on public networks. Therefore, we strongly advise against using it until it is fully implemented.

**Server Requirements:**
The server must be run on a system connected to a non-NAT network. NAT networks can pose challenges for the client side to locate the server over the internet. To address this issue, we have utilized IPV6 protocol. However, the widespread implementation of IPV6 addresses creates challenges, as some home networks do not have access to the IPV6 internet.

You NEED to create a SSL certificate in the project directory
use the terminal command - openssl req -newkey rsa:2048 -nodes -keyout server.key -x509 -days 365 -out server.crt ( Intall OpenSSL in your system )

**Client Setup:**
Before running the server, please verify your public IPV6 address and provide it to the server. While running the client, ensure that you provide the same IPV6 address as provided to the server. The client will not encounter any issues working over a NAT network, as the NAT system automatically handles this request.

**Server Scalability:**
The server can handle an unlimited number of clients, but it will require increased hardware and resources as the client count escalates. The default maximum client count is set to 5.

**End-to-End Encryption:**
The system will automatically initiate end-to-end encryption, eliminating the need for user intervention.

**Testing:**
Please contact me if any bugs arise. I have only tested this application on an Apple Silicon MacBook (ARM-based).

Thank you for exploring this project.
