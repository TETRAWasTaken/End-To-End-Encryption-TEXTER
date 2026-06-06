# End-To-End Encryption TEXTER

TEXTER is an end-to-end encrypted messaging project built around modern secure messaging primitives:
- **X3DH** for initial key agreement
- **Double Ratchet** for forward secrecy and post-compromise security
- **Encrypted message relay** where servers route ciphertext instead of plaintext

> ⚠️ Security note: this project is actively developed. Review and test thoroughly before production use.

---

## Project Architecture

The repository contains three main runtime parts:

1. **Rust Auth Server** (`/AuthServer`)
   - Handles register/login
   - Issues JWT session tokens
   - Issues short-lived WebSocket tickets

2. **Python WebSocket Server** (`/Server` + `/database`)
   - Manages real-time encrypted message routing
   - Stores user and protocol data in PostgreSQL
   - Caches undelivered encrypted messages

3. **Flet Client App** (`/TexterFlet`)
   - Local key generation/storage and cryptographic operations
   - Registration/login and friend flows
   - Encrypted chat UI

Optional in deployment: **Caddy reverse proxy** (see `.github/workflows/main_textere2ee.yml`) to expose one public entrypoint and route:
- `/api/auth/*` -> Rust auth service
- `/ws` -> Python WebSocket service

---

## Repository Layout

- `/AuthServer` - Rust authentication service (Axum + SQLx + Argon2 + JWT)
- `/Server` - FastAPI WebSocket service
- `/database` - DB pooling, storage helpers, and SQL schema (`x3dh_init.sql`)
- `/TexterFlet` - Flet client app and crypto/service layers
- `/requirements-server.txt` - Python server dependencies
- `/requirements.txt` - Client-oriented Python dependencies

---

## Prerequisites

Install the following before setup:

- **Python 3.11+** (3.12 works with project workflows)
- **Rust toolchain** (stable, with `cargo`)
- **PostgreSQL 14+**
- **OpenSSL** (if you want local TLS certificates)

---

## Local Setup (Step-by-Step)

### 1) Clone the repository

```bash
git clone https://github.com/TETRAWasTaken/End-To-End-Encryption-TEXTER.git
cd End-To-End-Encryption-TEXTER
```

### 2) Create and activate a Python virtual environment

```bash
python -m venv .venv
source .venv/bin/activate   # Windows PowerShell: .venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
```

### 3) Install Python dependencies

For server work:
```bash
pip install -r requirements-server.txt
```

For client work:
```bash
pip install -r requirements.txt
```

If you are developing both in one environment, install both requirement files.

### 4) Configure PostgreSQL

Create a database and user (example):

```sql
CREATE DATABASE texter_db;
CREATE USER texter_user WITH PASSWORD 'change_this_password';
GRANT ALL PRIVILEGES ON DATABASE texter_db TO texter_user;
```

Initialize schema:

```bash
psql "<postgres-connection-string>" -f database/x3dh_init.sql
```

### 5) Configure environment variables

#### Rust Auth Server (`/AuthServer`)
Required:
- `DATABASE_URL` (PostgreSQL DSN)

Recommended:
- `JWT_SECRET` (must match Python server value)
- `PORT` (defaults to `8001`)

Example:

```bash
export DATABASE_URL="<postgres-connection-string>"
export JWT_SECRET="replace-with-strong-random-secret"
export PORT="8001"
```

#### Python WebSocket Server (`/Server` + `/database`)
Use either:

**Option A: environment variables**
- `DB_HOST`
- `DB_NAME`
- `DB_USER`
- `DB_PASSWORD`
- `DB_PORT` (optional, default `5432`)
- `JWT_SECRET` (must match auth server)
- `ALGORITHM` (optional, default `HS256`)

Example:

```bash
export DB_HOST="localhost"
export DB_NAME="texter_db"
export DB_USER="texter_user"
export DB_PASSWORD="change_this_password"
export DB_PORT="5432"
export JWT_SECRET="replace-with-strong-random-secret"
export ALGORITHM="HS256"
```

**Option B: local `database.ini`**
Create a `database.ini` in repository root:

```ini
[postgresql]
host=localhost
database=texter_db
user=texter_user
password=your_db_password
port=5432
```

> `database.ini` is gitignored and intended for local development.

### 6) Start servers

#### Start Rust Auth Server

```bash
cd AuthServer
cargo run
```

#### Start Python WebSocket Server (new terminal)

```bash
cd /path/to/End-To-End-Encryption-TEXTER
python -m uvicorn Server.secure_asgi_server:app --host 127.0.0.1 --port 8002
```

### 7) (Optional) Run through a single gateway on port 8000

For one public entrypoint (`/api/auth/*` and `/ws` on same host), run with a reverse proxy (for example Caddy) similar to `.github/workflows/main_textere2ee.yml`.

### 8) Configure and run the client

Run the Flet client:

```bash
python TexterFlet/main.py
```

By default, the client targets the hosted endpoint defined in:
- `/TexterFlet/services/network_service.py`

To test local backend:
1. Update local addresses in `NetworkService` (`ws_uri` and `auth_url`) for `use_local=True`
2. Pass `use_local=True` where `AppController` is created in `/TexterFlet/main.py`

---

## Running Checks

From repository root:

```bash
# Rust service checks
cd AuthServer && cargo test

# Python syntax checks
cd .. && python -m compileall Server database TexterFlet
```

---

## Common Issues

- **Database connection fails**
  - Verify DB credentials/env vars
  - Ensure PostgreSQL is running and reachable

- **JWT ticket rejected / auth mismatch**
  - Ensure both servers use the same `JWT_SECRET`

- **WebSocket not connecting locally**
  - Confirm client points to your local host/IP and correct port
  - If using gateway, ensure `/ws` is routed to Python server

- **Schema initialization errors around UUID functions**
  - Enable PostgreSQL extension if needed:
    ```sql
    CREATE EXTENSION IF NOT EXISTS pgcrypto;
    ```

---

## Contributing

Contributions are welcome.

1. Fork the repository
2. Create a feature branch
3. Make focused changes with clear commit messages
4. Run checks (`cargo test`, `python -m compileall ...`)
5. Open a pull request with:
   - Problem summary
   - What changed
   - How you tested

Please keep changes scoped and avoid unrelated refactors in the same PR.

Also review the code of conduct: [`CODE_OF_CONDUCT.md`](./CODE_OF_CONDUCT.md)

---

## Security and Responsible Use

- Use this software only for legal and ethical purposes
- No system is perfectly secure; perform independent audits before sensitive deployment
- Report vulnerabilities via GitHub Issues with clear reproduction details

---

## License

This project is licensed under the terms in [`LICENSE`](./LICENSE).

---

## Maintainer

- GitHub: [@TETRAWasTaken](https://github.com/TETRAWasTaken)
