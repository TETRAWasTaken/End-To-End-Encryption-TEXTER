# Overview

TEXTER is a high-performance, secure messaging platform engineered from the ground up to protect user privacy. Utilizing the industry-standard Signal Protocol, TEXTER ensures that all communications are end-to-end encrypted. The architecture is split into a highly concurrent Rust authentication server, a Python ASGI WebSocket messaging server, and a cross-platform Flutter-based client deployed via Flet.

## Key Features

- **End-to-End Encryption (E2EE):** Fully implements the Extended Triple Diffie-Hellman (X3DH) key agreement protocol and the Double Ratchet algorithm for perfect forward secrecy and post-compromise security.

- **Cross-Platform Client:** Beautiful, responsive frontend built with Flet, supporting Windows, macOS, Linux, and Android seamlessly.

- **High-Performance Authentication:** A dedicated Rust-based authentication microservice ensuring rapid, secure logins and registrations.

- **Real-Time Communication:** Python ASGI WebSocket server for instant message delivery and caching.

- **Cloud-Ready:** Designed with deployment in mind, featuring GitHub Action workflows ready for cloud deployment to Azure and other providers.

## Architecture

TEXTER's modular architecture separates concerns to maximize security and performance:

- **`AuthServer/` (Rust):** Handles user registration, login, and identity verification safely and quickly.

- **`Server/` (Python/ASGI):** The core messaging broker handling secure WebSocket connections, message routing, and caching.

- **`TexterFlet/` (Python/Flet):** The client application housing the UI, local SQLite database, and cryptographic operations (`crypt_services.py`, `x3dh.py`, `double_ratchet.py`).

- **`database/`:** Shared schemas and initialization scripts for key storage and user data.

## Getting Started

### Prerequisites

- Python 3.10+
- Rust & Cargo

### 1. Clone the Repository

```bash
git clone https://github.com/tetrawastaken/end-to-end-encryption-texter.git
cd end-to-end-encryption-texter
```

### 2. Run the Auth Server (Rust)

```bash
cd AuthServer
cargo build --release
cargo run
```

### 3. Run the Messaging Server (Python)

Open a new terminal in the project root:

```bash
pip install -r requirements-server.txt
cd Server
python secure_asgi_server.py
```

### 4. Launch the Client (Flet)

Open a new terminal in the project root:

```bash
cd TexterFlet
pip install -r requirements.txt
flet run main.py
```

## 🛠️ Deployment

GitHub Actions workflows are included in `.github/workflows/` for automated packaging:

- **`windows_client.yml`**: Compiles the Flet app into a standalone Windows executable.
- **`android_pkg.yml`**: Builds the Android APK.
- **`main_textere2ee.yml`**: CI/CD pipeline for server-side cloud deployment.

## 🤝 Contributing

Contributions make the open-source community an amazing place to learn, inspire, and create. Any contributions you make are greatly appreciated.

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

Please ensure you review our CODE_OF_CONDUCT.md before participating.

## 📝 License

Distributed under the appropriate open-source license. See the LICENSE file for more information.

## 📬 Contact & Author

**Anshumaan Soni**
- **Project Link:** https://github.com/tetrawastaken/end-to-end-encryption-texter

*Built with 💙 for privacy and secure communication.*