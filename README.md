# End-To-End Encryption TEXTER

A secure messaging application with end-to-end encryption using X3DH and Double Ratchet protocols.

---

## ⚠️ IMPORTANT WARNINGS

**YOU ARE SOLELY RESPONSIBLE** for how you use this software. The developers bear **NO RESPONSIBILITY** for illegal activities or misuse.

### Critical Notices

- **PROVIDED "AS IS"**: No warranty. Use at your own risk.
- **DEVELOPMENT STATUS**: Still in active development. May contain bugs or vulnerabilities. Do not use for critical security applications without thorough auditing.
- **PRIVACY**: Message content is encrypted end-to-end. Metadata (who communicates with whom, when) may be observable by server operators or network monitors.
- **NO SYSTEM IS 100% SECURE**: No encryption system is perfect.
- **LEGAL COMPLIANCE**: You must comply with all applicable laws in your jurisdiction.

---

## 🔒 Security Features

- **X3DH Protocol**: Secure key exchange
- **Double Ratchet**: Forward secrecy and break-in recovery
- **Curve25519**: Elliptic curve cryptography
- **AES-GCM**: Message encryption
- **Server Cannot Read Messages**: Server only routes encrypted data
- **SSL/TLS**: Transport layer security

### Best Practices

- Use strong, unique passwords
- Keep software updated
- Protect your device (private keys stored locally)
- Verify server identity before connecting
- Report security vulnerabilities responsibly

---

## 📋 Quick Start

### Prerequisites

- Python 3.8+
- PostgreSQL 12+
- OpenSSL (for SSL certificates)

### Installation

```bash
# Clone repository
git clone https://github.com/TETRAWasTaken/End-To-End-Encryption-TEXTER.git
cd End-To-End-Encryption-TEXTER

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Set up PostgreSQL database
sudo -u postgres psql
CREATE DATABASE texter_db;
CREATE USER texter_user WITH PASSWORD 'your_password';
GRANT ALL PRIVILEGES ON DATABASE texter_db TO texter_user;
\q

# Generate SSL certificate (for development)
openssl req -newkey rsa:2048 -nodes -keyout server.key -x509 -days 365 -out server.crt
```

⚠️ **For production**: Use certificates from a trusted CA (e.g., Let's Encrypt)

### Configuration

- Update database credentials in `database/DB_connect.py`
- Default server binds to `::1` (IPv6 localhost). Modify `Server/secure_asgi_server.py` for external access.

### Usage

**Start Server:**
```bash
uvicorn Server.secure_asgi_server:app --host :: --port 8000
```

**Start Client (in new terminal):**
```bash
python TEXTERE2EE.py
```

---

## 🐛 Common Issues

**SSL Certificate Errors**: Ensure `server.crt` and `server.key` exist. Self-signed certificates require manual trust.

**Database Connection**: Verify PostgreSQL is running and credentials are correct.

**IPv6 Issues**: Check IPv6 support with `ping6 ::1`. Some networks require IPv4 (code modification needed).

**Network Access**: Open firewall port (e.g., `sudo ufw allow 8000`). Use public IPv6 address for external connections.

**Import Errors**: Ensure virtual environment is activated and dependencies are installed.

---

## 📞 Contact

- **GitHub Issues**: [Report bugs](https://github.com/TETRAWasTaken/End-To-End-Encryption-TEXTER/issues)
- **Maintainer**: TETRAWasTaken

---

## ⚖️ Legal Reminder

**Use for legitimate privacy purposes only. You accept full responsibility for your actions. Illegal activity is YOUR accountability. Developers accept no liability for misuse.**
