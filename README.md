# Login and Registration System (C++)

A fully functional console-based Login and Registration System built with C++ using Object-Oriented Programming principles.

## Features

| Feature | Details |
|---|---|
| **Registration** | Username/password validation, duplicate detection, password confirmation |
| **Login** | Credential verification with **3-attempt lockout** |
| **Dashboard** | View account info, change password, logout |
| **Security** | **SHA-256 hashing** with per-user random salt (no plaintext passwords) |
| **Persistence** | File-backed storage with atomic writes and corruption recovery |
| **Input Masking** | Passwords displayed as `****` in the terminal |

## Project Structure

```
login-system/
├── CMakeLists.txt
├── .gitignore
├── README.md
├── include/
│   ├── Auth.h              # Authentication controller
│   ├── Dashboard.h         # Post-login user dashboard
│   ├── Hasher.h            # SHA-256 + salt (FIPS 180-4)
│   ├── InputValidator.h    # Username & password policy
│   ├── User.h              # User data model
│   └── UserDatabase.h      # File-backed user storage
├── src/
│   ├── main.cpp            # Entry point & main menu
│   ├── Auth.cpp
│   ├── Dashboard.cpp
│   ├── Hasher.cpp
│   ├── InputValidator.cpp
│   ├── User.cpp
│   └── UserDatabase.cpp
└── data/                   # users.dat created at runtime
```

## Compilation

### Using g++ (MinGW / GCC)

```bash
g++ -std=c++14 -Wall -Wextra -O2 -Iinclude \
    src/Hasher.cpp src/User.cpp src/UserDatabase.cpp \
    src/InputValidator.cpp src/Auth.cpp src/Dashboard.cpp \
    src/main.cpp -o login_system.exe
```

### Using CMake

```bash
mkdir build && cd build
cmake ..
cmake --build .
```

### Run

```bash
./login_system.exe
```

## Sample Execution

```
==========================================
   LOGIN AND REGISTRATION SYSTEM (C++17)
==========================================

  [1] Register
  [2] Login
  [3] Exit
  Select > 1

========== REGISTER ==========
  Username : alice
  Password : ********
  Confirm  : ********
  [OK] Registration successful! You may now log in.

  Select > 2

============ LOGIN ===========
  Username : alice
  Password : ********
  [OK] Login successful!

======================================
       WELCOME TO YOUR DASHBOARD
======================================
  Logged in as: alice

  [1] View Account Info
  [2] Change Password
  [3] Logout
  Select > 1

---------- Account Info ----------
  Username    : alice
  Created at  : 2026-11-16_14:30:47
  Login count : 1
  Password    : ******** (hashed)
----------------------------------
```

## Security Design

- **No plaintext passwords** — all passwords are hashed with SHA-256 before storage
- **Per-user random salt** — 16-byte cryptographic salt prevents rainbow table attacks
- **Constant-time comparison** — `Hasher::verify()` uses XOR accumulation to prevent timing side-channels
- **Password policy** — minimum 8 chars, requires uppercase + lowercase + digit + special character
- **Login lockout** — 3 failed attempts per login session
- **Atomic file writes** — write-to-temp + rename pattern prevents data corruption
- **Corruption recovery** — malformed records are skipped with warnings; valid records still load
- **Input masking** — passwords shown as `*` on terminal (falls back to hidden input on POSIX)

## C++ Concepts Used

- **Classes & OOP** — `User`, `UserDatabase`, `Auth`, `Dashboard`, `Hasher`, `InputValidator`
- **Encapsulation** — private data with public accessors
- **File I/O** — `fstream` with error checking and atomic writes
- **String manipulation** — parsing, serialization, hex encoding
- **Cryptography** — SHA-256 implemented from FIPS 180-4 specification
- **Cross-platform** — Windows (`_getch`, `GetConsoleMode`) and POSIX (`termios`) support
- **STL containers** — `unordered_map`, `array`, `pair`

## License

MIT
