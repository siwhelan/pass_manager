# Password Manager 🔒🗝️💻

A simple command-line password manager using Python, MongoDB, and encryption.

**Disclaimer:** This is a work in progress and should not be used in real-world scenarios. The security of the implementation has not been thoroughly tested or audited. Use at your own risk.

## Features

- Register a new user with a master password
- Store and retrieve encrypted passwords
- Generate random passwords based on user preferences
- Encrypt and decrypt passwords using AES and PBKDF2

## Dependencies

- `pymongo`
- `bcrypt`
- `pycryptodome`
- `pyperclip`

## Usage

1. Install the required dependencies:

```bash
pip install pymongo bcrypt pycryptodome pyperclip
```

Ensure a MongoDB server is running locally on the default port (27017).

Run the vault.py script:

```bash

python vault.py
```

Follow the prompts to register a new user, store a password, retrieve a password, or generate a random password.
