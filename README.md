# End-to-End Encrypted Chat Application

A web-based chat application that provides end-to-end encrypted messaging and file sharing. Messages and files are encrypted in the browser; the server can never see their contents.

## 🎯 Features

- **🔐 End-to-end encryption (E2EE):** Messages and files are encrypted in the browser, the server cannot read them
- **🧩 Hybrid cryptography:** AES-256 (message/file) + RSA-2048 (key exchange)
- **⚡ Real-time messaging:** Instant delivery via Socket.IO
- **📁 File sharing:** Chunked upload for large files (up to 100 MB)
- **👥 User search:** Search users by username
- **✓✓ Read receipts:** Message status tracking (sent, delivered, read)
- **🛡️ Admin panel:** Live monitoring, statistics, crypto analysis
- **📊 TCP performance simulation:** RTT measurement and congestion control charts

## 🛠️ Technologies Used

| Layer | Technology |
|---|---|
| **Frontend** | HTML5, CSS3, JavaScript |
| **Cryptography (Frontend)** | CryptoJS (AES-256), JSEncrypt (RSA-2048) |
| **Real-time** | Socket.IO 4.5.4 |
| **Backend** | Python 3.12, Flask 3.0 |
| **WebSocket** | Flask-SocketIO 5.3 |
| **Database** | MySQL 8.0 |
| **Authentication** | JWT (PyJWT 2.8) |
| **Charts (Admin)** | Chart.js 4.4 |

## 📁 Project Structure

```text
end_to_end_chat_app/
├── main.py                     # Main Flask application
├── config.py                   # Configuration (DB, SECRET_KEY)
├── admin_monitor.py            # Admin panel blueprint
├── requirements.txt            # Python dependencies
├── .env.example                # Environment variables template
├── .gitignore                  # Files ignored by Git
├── README.md                   # This file
│
├── templates/                  # HTML templates (Jinja2)
│   ├── index.html              # Landing page
│   ├── register.html           # Registration page (RSA key generation)
│   ├── login.html              # Login page
│   ├── chat.html               # Chat interface
│   └── admin_monitor.html      # Admin panel
│
├── static/                     # CSS/JS files
│   └── style.css
│
├── uploads/                    # Uploaded files (not tracked in Git)
│
└── archive/                    # Old manual cryptography implementations
    ├── encryption.py           # (Educational) AES-256 implementation
    ├── decrption.py            # (Educational) AES-256 decryption
    ├── file_encryption.py      # (Educational) File encryption
    ├── file_decryption.py      # (Educational) File decryption
    ├── key_creations.py        # (Educational) RSA key generation
    └── client.py               # Old Python CLI client
```

## 🔐 Encryption Architecture

This project uses **true end-to-end encryption (E2EE)**. The server can **never** see the contents of messages or files.

### Registration Flow

1. User opens `/register`
2. An **RSA-2048** key pair is generated in the browser (JSEncrypt)
3. The **public key** is sent to the server → `users.public_key` (MySQL)
4. The **private key** stays in the browser → `localStorage` (never sent to the server)

### Message Sending Flow

1. Sender fetches the recipient's **public key** (`/api/users/<id>/public-key`)
2. A random **AES-256 key** is generated in the browser (CryptoJS)
3. The message is encrypted with **AES-256** → `encrypted_message`
4. The AES key is encrypted with the recipient's **RSA public key** → `encrypted_aes_key`
5. Both encrypted values are sent to the server
6. The server **only stores them**; it cannot decrypt them

### Message Receiving Flow

1. Recipient fetches messages via `/api/messages`
2. Decrypts `encrypted_aes_key` with their **RSA private key** → obtains the AES key
3. Decrypts `encrypted_message` with the AES key → plaintext
4. Message is displayed on screen

### File Sharing

The same hybrid approach applies to files:

- File is encrypted with **AES-256**
- AES key is encrypted with **RSA-2048**
- File is uploaded in **chunks** (`file_info` + `file_pieces` tables)
- Recipient downloads and decrypts the file in the browser

### Why the Server Cannot Read Anything

| Data | Stored on Server | Encrypted With | Decryptable by Server? |
|---|---|---|---|
| Message content | `messages.encrypted_message` | AES-256 | ❌ No |
| AES key | `messages.encrypted_aes_key` | RSA-2048 (recipient's public key) | ❌ No |
| File content | `file_pieces.encrypted_piece` | AES-256 | ❌ No |
| File AES key | `file_info.encrypted_aes_key` | RSA-2048 (recipient's public key) | ❌ No |
| Private keys | ❌ Not stored | — | — |

## 🚀 Installation

### 1. Clone the Repository

```bash
git clone https://github.com/TurgayBU/end_to_end_chat_app.git
cd end_to_end_chat_app
```

### 2. Create a Virtual Environment

```bash
python -m venv venv
source venv/bin/activate        # macOS/Linux
venv\Scripts\activate           # Windows
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Set Up the MySQL Database

```sql
CREATE DATABASE chatapp CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
```

**Note:** Tables are created automatically by the `init_database()` function when `main.py` runs.

### 5. Configure Environment Variables

```bash
cp .env.example .env
```

Open `.env` and set your own values:

```env
SECRET_KEY=<32-byte-random-key>
DB_HOST=localhost
DB_NAME=chatapp
DB_USER=root
DB_PASSWORD=<your-mysql-password>
CORS_ORIGINS=http://localhost:5001
ADMIN_SECRET=<random-key-for-admin>
```

**To generate a random key:**

```bash
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

### 6. Run the Application

```bash
python main.py
```

Open in your browser: **http://localhost:5001**

## 🎮 Usage

### User (Customer)

1. **Register** → RSA keys are generated automatically on `/register`
2. **Back up your private key** → Click "💾 Backup Private Key" to download it
3. **Log in** → Use your username
4. **Chat** → Select a user from the left panel and send messages
5. **Share files** → Use the 📁 button to send files (max 100 MB)

> ⚠️ **IMPORTANT:** If you lose your private key, you **cannot decrypt old messages**. Always back it up.

### Admin

1. **Start the server** → A **one-time setup link** appears in the console
2. **Click the link** → An admin token is generated (usable once)
3. **Go to the admin panel** → `/admin/monitor?admin_token=<TOKEN>`
4. **Monitor** → Conversations, statistics, crypto analysis, TCP simulation

The console output when starting the server looks like this:

```text
============================================================
              🔐 ADMIN SETUP LINK (ONE-TIME USE)
============================================================

   http://localhost:5001/admin/setup/xY3kL9mN2pQ7rT4vW8zA1bC5dE6fG0hJ

   ⚠️ This link can be used ONLY ONCE!
   ⚠️ It becomes invalid after use.
   ⚠️ A new link is generated when the server restarts.
============================================================
```

## 🔬 Technical Decisions and Development History

This project went through **two architectural phases**. The transition to the second phase was a **deliberate decision** based on the technical reasons below.

### Phase 1: Manual Cryptography (Initial Version)

In the first version of the project, to deeply understand cryptographic concepts, I **implemented AES-256 and RSA algorithms from scratch in Python**:

- `archive/encryption.py` — AES-256 block encryption (S-Box, MixColumns, Key Expansion)
- `archive/decrption.py` — AES-256 block decryption
- `archive/key_creations.py` — RSA key generation (Miller-Rabin primality test)
- `archive/client.py` — Python CLI client
- `archive/file_encryption.py` / `archive/file_decryption.py` — File encryption

**What I learned:**

- Internal workings of AES (S-Box, ShiftRows, MixColumns, Key Expansion)
- Mathematical foundations of RSA (modular arithmetic, Miller-Rabin primality test)
- Hybrid cryptography (using AES + RSA together)

### Phase 2: Web-Based Architecture (Current Version)

When the project was moved to a web interface, I switched to industry-standard JavaScript libraries for the following **technical reasons**:

| Reason | Explanation |
|---|---|
| **Security** | My manual AES implementation mishandled `0x00` bytes and had incorrect PKCS#7 padding. Industry-standard libraries do not contain such bugs. |
| **Performance** | The pure Python implementation was very slow for large files. CryptoJS runs optimized in the browser. |
| **Key Management** | Storing the private key in the browser via `localStorage` is far more secure than sending it to the server (true E2EE). |
| **Maintenance Cost** | Using actively maintained libraries is more sustainable than maintaining my own code. |
| **Compatibility** | CryptoJS and JSEncrypt are tested for cross-browser compatibility and security updates. |

**Libraries used:**

- [CryptoJS](https://cryptojs.gitbook.io/docs/) — AES-256 encryption
- [JSEncrypt](https://github.com/travist/jsencrypt) — RSA-2048 key management
- [Socket.IO](https://socket.io/) — Real-time communication

### Why Archive Instead of Delete?

The manual implementations were **not deleted**, but moved to the `archive/` folder. Reasons:

1. **Reference value:** They can serve as a basis if a similar need arises in the future.
2. **Learning record:** Tangible proof of how I learned cryptography.
3. **Portfolio:** An answer to the "why didn't you write it yourself?" question in technical interviews.
4. **Transparency:** Shows the project's development history.

> **Note:** The code in this archive should **not be used in production**. It is for educational purposes and contains known security vulnerabilities.

## 📚 Archive — Manual Cryptography Implementations

The `archive/` folder contains the manual AES-256 and RSA implementations used in the **initial version** of the project.

### Contents

| File | Description |
|---|---|
| `encryption.py` | AES-256 block encryption (S-Box, MixColumns, Key Expansion) |
| `decrption.py` | AES-256 block decryption |
| `file_encryption.py` | File encryption |
| `file_decryption.py` | File decryption |
| `key_creations.py` | RSA key generation (Miller-Rabin primality test) |
| `client.py` | Python CLI client (terminal-based) |

### ⚠️ Warning

These files should **not be used in production**. They are for educational purposes and contain known security vulnerabilities:

- The `_matrix_to_text` function skips `0x00` bytes → binary data is corrupted
- AES keys are derived from the RSA public key → insecure
- `s_box` is undefined in some files → will not run
- The `rsa_keys` table does not exist in the main `main.py` → will not run
- `client.py` uses port 5000 while `main.py` uses 5001 → incompatible

### 📖 Educational Value

These files can be used as a **reference** for the following topics:

- AES-256 block encryption (S-Box, MixColumns, Key Expansion)
- RSA key generation (Miller-Rabin primality test)
- Hybrid cryptography (using AES + RSA together)
- Low-level cryptography implementation in Python

## ⚙️ Configuration

| Setting | File | Variable |
|---|---|---|
| Flask port | `main.py` | `socketio.run(app, port=5001)` |
| Database | `.env` | `DB_HOST`, `DB_NAME`, `DB_USER`, `DB_PASSWORD` |
| JWT Secret | `.env` | `SECRET_KEY` |
| Admin Secret | `.env` | `ADMIN_SECRET` |
| CORS | `.env` | `CORS_ORIGINS` |
| Upload folder | `config.py` | `UPLOAD_FOLDER` |
| Max file size | `config.py` | `MAX_CONTENT_LENGTH` (100 MB) |

> ⚠️ **Security Note:** Sensitive information such as `SECRET_KEY` and `ADMIN_SECRET` should **never** be hard-coded. They must be stored in the `.env` file, which is listed in `.gitignore` and therefore never committed to Git.

## 📌 Notes

- The `uploads/` folder is created automatically at runtime
- Private keys are stored in `localStorage` and are **never** sent to the server
- Messages and files are encrypted with **AES-256**; AES keys are encrypted with **RSA-2048**
- The **TCP RTT** and **Congestion Control** charts in the admin panel are for network performance simulation
- The one-time setup link for the admin panel is printed to the console at server startup

## 👤 Developers

- **TurgayBU** — [GitHub](https://github.com/TurgayBU)
- **Radiant28** — [GitHub](https://github.com/Radiant28)

## 📄 License

This project currently has no license specified. You may add an MIT license if you wish.

## 🙏 Acknowledgements

This project is a product of my cryptography learning journey. The transition from manual implementation to industry-standard libraries reflects the principle of **"using the right tool in the right place."**