# Password Manager 🔒🗝️💻

A simple command-line password manager using Python, MongoDB, and encryption.

Following on from my recent take on [password generators](https://github.com/siwhelan/pass_gen) | [(Live Demo)](https://pass-gen-gray.vercel.app/), this is a deeper dive into encryption, password management and storage - something that I've long had an interest in! 

This program uses MongoDB to store the passwords, AES encryption to securely store them, and bcrypt for hashing.

**Disclaimer:** This is a work in progress and should not be used in real-world scenarios. The security of the implementation has not been thoroughly tested or audited. Use at your own risk.

## Features

- Register a new user with a master password
- Store and retrieve encrypted passwords
- Generate random passwords based on user preferences
- Encrypt and decrypt passwords using AES and PBKDF2

### register_user(): 

This function is used to register a new user by taking a unique user ID and master password as input. The master password is hashed using bcrypt and stored in the MongoDB database.

### user_exists(user_id): 

This function checks if a user ID already exists in the database.

### login(user_id): 

This function prompts the user to enter the master password and verifies it against the hashed master password stored in the database.

### generate_random_password(): 

This function generates a random password based on the user's preferences for length, numbers, and special characters.

### encrypt_password(password, key): 

This function encrypts the input password using the AES cipher with the provided key.

### decrypt_password(ciphertext, key): 

This function decrypts the input ciphertext using the AES cipher with the provided key.

### store_password(master_password): 

This function takes the master password and prompts the user for the login username, password choice (create or generate), and label. It then encrypts the password and stores it along with the username and label in the MongoDB database.

### retrieve_password(): 

This function prompts the user for the master password and the label of the password they want to retrieve. It then decrypts the password and copies it to the clipboard for the user to paste where needed.

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
