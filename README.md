# End-To-End Encryption TEXTER

A secure, end-to-end encrypted messaging application built with Python, featuring modern cryptographic protocols for private communication.

---

##  IMPORTANT LEGAL DISCLAIMER AND WARNINGS 

**READ THIS CAREFULLY BEFORE USING THIS SOFTWARE**

### User Responsibility and Legal Accountability

1. **YOU ARE SOLELY RESPONSIBLE** for how you use this software. The developers, contributors, and maintainers of this project bear **NO RESPONSIBILITY** for any illegal activities, misuse, or harmful actions conducted using this application.

2. **ILLEGAL ACTIVITY**: Any illegal activity conducted through this messaging service is **YOUR OWN ACCOUNTABILITY**. This includes but is not limited to:
   - Sharing illegal content
   - Planning or coordinating illegal activities
   - Harassment, threats, or cyberbullying
   - Distribution of copyrighted material without authorization
   - Any violation of local, state, national, or international laws

3. **COMPLIANCE WITH LAWS**: You are responsible for ensuring your use of this software complies with all applicable laws and regulations in your jurisdiction.

4. **NO WARRANTY**: This software is provided "AS IS" without warranty of any kind. Use at your own risk.

5. **DEVELOPMENT STATUS**: This application is still in active development. While it implements end-to-end encryption using X3DH and Double Ratchet protocols, it may contain bugs or vulnerabilities. Do not rely on it for critical security applications without thorough auditing.

6. **PRIVACY**: While this application uses end-to-end encryption to protect message content, metadata (such as who is communicating and when) may still be observable by server operators or network monitors.

### Security Warning

- This software implements cryptographic protocols for educational and legitimate privacy purposes only.
- The encryption is designed to protect your communications, but no system is 100% secure.
- Always keep your software updated and follow security best practices.

**By using this software, you acknowledge that you have read, understood, and agree to these terms. You accept full responsibility for your actions.**

---

## 📋 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Architecture](#architecture)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [SSL Certificate Setup](#ssl-certificate-setup)
- [Configuration](#configuration)
- [Usage](#usage)
- [Security Features](#security-features)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [License](#license)

---

## 🔍 Overview

End-To-End Encryption TEXTER is a messaging application that prioritizes user privacy and security. It uses modern cryptographic protocols (X3DH for key exchange and Double Ratchet for message encryption) to ensure that only the intended recipients can read your messages.

**Key Characteristics:**
- Client-Server architecture with WebSocket communication
- End-to-end encryption (server cannot read message content)
- Built with Python, PySide6 (Qt), and asyncio
- Uses IPv6 for networking
- PostgreSQL database for user management

---

## ✨ Features

- **End-to-End Encryption**: Messages are encrypted on the sender's device and can only be decrypted by the recipient
- **X3DH Protocol**: Secure key agreement protocol for initial key exchange
- **Double Ratchet Algorithm**: Provides forward secrecy and break-in recovery
- **User Authentication**: Secure user registration and login system
- **Modern GUI**: Built with PySide6 for a smooth user experience
- **Asynchronous Architecture**: Efficient handling of multiple concurrent connections
- **SSL/TLS Support**: Encrypted transport layer for additional security

---

## 🏗️ Architecture

### Components

1. **Client Application** (`TEXTERE2EE.py` + `Client/` directory)
   - GUI built with PySide6 (Qt)
   - Async networking with WebSockets
   - Cryptographic services (X3DH, Double Ratchet)
   - Local key management

2. **Server** (`NewServerCode/` directory)
   - ASGI-compatible server (runs with uvicorn)
   - WebSocket-based communication
   - User authentication and management
   - PostgreSQL database for user data
   - Message routing (does not decrypt messages)

3. **Database**
   - PostgreSQL for persistent storage
   - Stores user credentials and public keys
   - Does not store message content (E2EE)

### Cryptographic Protocols

- **X3DH (Extended Triple Diffie-Hellman)**: Initial key agreement
- **Double Ratchet**: Session encryption with forward secrecy
- **Curve25519**: Elliptic curve cryptography for key exchange
- **AES-GCM**: Symmetric encryption for message content

---

## 📦 Prerequisites

### System Requirements

- **Python**: 3.8 or higher
- **PostgreSQL**: 12 or higher
- **OpenSSL**: For generating SSL certificates
- **IPv6**: Network support for IPv6 (optional but recommended)

### Supported Platforms

- Linux
- macOS (tested on Apple Silicon)
- Windows (may require additional configuration)

---

## 🚀 Installation

### 1. Clone the Repository

```bash
git clone https://github.com/TETRAWasTaken/End-To-End-Encryption-TEXTER.git
cd End-To-End-Encryption-TEXTER
```

### 2. Set Up Python Environment

It's recommended to use a virtual environment:

```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### 3. Install Dependencies

**For Server:**
```bash
pip install -r requirements-server.txt
```

**For Client:**
```bash
pip install -r requirements.txt
```

**For Both (if running on same machine):**
```bash
pip install -r requirements.txt
```

### 4. Set Up PostgreSQL Database

Install PostgreSQL and create a database:

```bash
# Install PostgreSQL (method varies by OS)
# Ubuntu/Debian:
sudo apt-get install postgresql postgresql-contrib

# macOS:
brew install postgresql

# Create database
sudo -u postgres psql
CREATE DATABASE texter_db;
CREATE USER texter_user WITH PASSWORD 'your_secure_password';
GRANT ALL PRIVILEGES ON DATABASE texter_db TO texter_user;
\q
```

Update the database connection settings in your server configuration files.

---

## 🔐 SSL Certificate Setup

**IMPORTANT**: SSL certificates are required for secure communication.

### For Local Development/Testing

Generate a self-signed certificate:

```bash
openssl req -newkey rsa:2048 -nodes -keyout server.key -x509 -days 365 -out server.crt
```

You'll be prompted to enter certificate details. For local testing, you can use default values or enter your information.

**Files created:**
- `server.key` - Private key (keep this secure!)
- `server.crt` - Certificate (can be shared with clients)

**⚠️ Security Note**: Self-signed certificates will show security warnings in browsers and may require manual acceptance. For production use, obtain certificates from a trusted Certificate Authority (Let's Encrypt, etc.).

### For Production

Use a proper SSL certificate from a trusted Certificate Authority:
- [Let's Encrypt](https://letsencrypt.org/) (free)
- Commercial CAs (Digicert, GlobalSign, etc.)

### For Cloud Deployment (Azure, AWS, etc.)

If deploying to a cloud platform, SSL is typically handled by the load balancer. The application detects Azure deployment automatically and disables internal SSL handling.

---

## ⚙️ Configuration

### Server Configuration

1. **Database Connection**: Update database credentials in `database/DB_connect.py` (if needed)

2. **Host and Port**: By default, the server binds to `::1` (IPv6 localhost). For external access, modify the host in `NewServerCode/secure_asgi_server.py`

3. **Find Your Public IPv6 Address**:
   ```bash
   # Linux/macOS
   curl -6 ifconfig.co
   
   # Or check your network settings
   ip -6 addr show  # Linux
   ifconfig         # macOS
   ```

### Client Configuration

When you run the client, you'll need to provide:
- **Server IPv6 Address**: The public IPv6 address of the server
- **Port**: Default is typically 8000 (check server configuration)
- **Username and Password**: For authentication

---

## 🎯 Usage

### Running the Server

1. **Ensure PostgreSQL is running**:
   ```bash
   # Check status (varies by OS)
   sudo systemctl status postgresql  # Linux
   brew services list                # macOS
   ```

2. **Navigate to project directory**:
   ```bash
   cd /path/to/End-To-End-Encryption-TEXTER
   ```

3. **Run the server**:
   ```bash
   # Using uvicorn (recommended)
   uvicorn NewServerCode.secure_asgi_server:app --host :: --port 8000
   
   # Or if using the included script
   python -m NewServerCode.secure_asgi_server
   ```

4. **Verify server is running**:
   - Look for "Application startup complete" message
   - Note the address and port

### Running the Client

1. **Open a new terminal** (keep server running in the first terminal)

2. **Activate the same virtual environment**:
   ```bash
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Run the client application**:
   ```bash
   python TEXTERE2EE.py
   ```

4. **Login or Register**:
   - On first run, create a new account
   - Enter the server's IPv6 address when prompted
   - Choose a username and strong password

5. **Start Messaging**:
   - The application will automatically handle encryption
   - Send messages securely to other users

### Running Multiple Clients

To test with multiple users:
1. Run the client in different terminals or machines
2. Register different usernames for each client
3. All clients should connect to the same server address

---

## 🔒 Security Features

### End-to-End Encryption

- **Message Encryption**: All message content is encrypted on the sender's device before transmission
- **Server Cannot Read Messages**: The server only routes encrypted messages; it cannot decrypt them
- **Key Exchange**: X3DH protocol ensures secure initial key agreement
- **Forward Secrecy**: Double Ratchet provides forward secrecy - compromising current keys doesn't expose past messages
- **Break-in Recovery**: Even if keys are compromised, the system can recover security for future messages

### Authentication

- User registration with password hashing
- Session management with secure tokens
- Protection against unauthorized access

### Transport Security

- SSL/TLS encryption for all network communication
- Protects against man-in-the-middle attacks
- Certificate-based server authentication

### Best Practices

1. **Strong Passwords**: Use long, unique passwords for your account
2. **Keep Software Updated**: Regularly pull updates from the repository
3. **Secure Your Keys**: The application stores private keys locally - protect your device
4. **Verify Server**: Ensure you're connecting to the legitimate server
5. **Report Vulnerabilities**: If you find security issues, report them responsibly

---

## 🐛 Troubleshooting

### Common Issues

#### 1. SSL Certificate Errors

**Problem**: "SSL certificate verification failed"

**Solution**:
- Ensure `server.crt` and `server.key` exist in the project directory
- For self-signed certificates, you may need to add an exception in the client
- Verify certificate hasn't expired (check with `openssl x509 -in server.crt -text`)

#### 2. Database Connection Issues

**Problem**: "Could not connect to database"

**Solutions**:
- Verify PostgreSQL is running: `sudo systemctl status postgresql`
- Check database credentials in configuration files
- Ensure database exists: `psql -l`
- Check firewall rules if connecting remotely

#### 3. IPv6 Not Available

**Problem**: "Network unreachable" or "Cannot bind to IPv6"

**Solutions**:
- Check IPv6 support: `ping6 ::1`
- Some networks don't support IPv6 - consider using IPv4 (requires code modification)
- For server, ensure IPv6 is enabled on your router/network
- Try using localhost for testing: `::1` (IPv6) or `127.0.0.1` (IPv4)

#### 4. Server Not Accessible Over Network

**Problem**: Client can't connect to server from different machine

**Solutions**:
- **NAT Networks**: Server must be on a publicly accessible network or use port forwarding
- **Firewall**: Open the server port (default 8000): `sudo ufw allow 8000`
- **IPv6 Routing**: Ensure your router properly routes IPv6
- **IP Address**: Use your public IPv6 address, not local address
- **Cloud Deployment**: Ensure security groups/firewall rules allow traffic

#### 5. Import Errors

**Problem**: "ModuleNotFoundError" or "ImportError"

**Solutions**:
- Ensure virtual environment is activated
- Reinstall dependencies: `pip install -r requirements.txt`
- Check Python version: `python --version` (should be 3.8+)

#### 6. GUI Not Appearing

**Problem**: Client runs but no window appears

**Solutions**:
- Check if running on a system with display/GUI support
- Install Qt dependencies (Linux): `sudo apt-get install libxcb-xinerama0`
- Try running with verbose output to see errors

### Getting Help

If you encounter issues not covered here:

1. **Check Existing Issues**: Look at GitHub Issues for similar problems
2. **Enable Debug Logging**: Modify the code to add verbose logging
3. **Report Bugs**: Create a detailed issue report with:
   - Operating system and version
   - Python version
   - Full error message and stack trace
   - Steps to reproduce
4. **Contact**: Reach out to the project maintainer

**Note**: This project has been primarily tested on Apple Silicon MacBooks (ARM-based). Testing on other platforms is ongoing.

---

## 👥 Contributing

Contributions are welcome! However, please note:

1. **Security Focus**: This project handles sensitive cryptographic operations. All contributions will be carefully reviewed.
2. **Code Quality**: Follow existing code style and conventions
3. **Testing**: Test your changes thoroughly before submitting
4. **Documentation**: Update documentation for new features

### How to Contribute

1. Fork the repository
2. Create a feature branch: `git checkout -b feature-name`
3. Make your changes
4. Test thoroughly
5. Commit with clear messages: `git commit -m "Add feature description"`
6. Push to your fork: `git push origin feature-name`
7. Create a Pull Request

---

## 📄 License

This project is open source. Please check the repository for specific license information.

---

## 📞 Contact

For questions, bug reports, or security concerns:
- **GitHub Issues**: [Create an issue](https://github.com/TETRAWasTaken/End-To-End-Encryption-TEXTER/issues)
- **Project Maintainer**: TETRAWasTaken

---

## 🙏 Acknowledgments

This project implements cryptographic protocols based on:
- **Signal Protocol**: X3DH and Double Ratchet algorithms
- **Cryptography Library**: Python cryptography package
- **PySide6**: Qt for Python GUI framework

---

## ⚖️ Final Reminder

**This software is provided for legitimate privacy and security purposes only. You are solely responsible for how you use it. Any illegal activity conducted through this application is your own accountability. The developers and contributors accept no liability for misuse.**

**Use responsibly. Respect laws. Protect privacy.**
