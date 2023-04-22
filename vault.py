from bson.binary import Binary
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Protocol.KDF import PBKDF2
import pymongo
import bcrypt
from getpass import getpass
import pyperclip
import string
import secrets

# Connect to MongoDB
client = pymongo.MongoClient("mongodb://localhost:27017/")
db = client["vault"]


# Function to register a new user
def register_user():
    user_id = input("Enter a unique user ID: ")

    if db["users"].count_documents({"user_id": user_id}) > 0:
        print("User ID already exists. Please choose another.")
        return register_user()

    master_password = getpass("Enter your master password: ")
    master_password_hash = bcrypt.hashpw(
        master_password.encode(), bcrypt.gensalt()
    )

    db["users"].insert_one(
        {"user_id": user_id, "master_password": master_password_hash}
    )
    print("Registration successful. Your user ID is:", user_id)


# register_user()


# Function to check if a user exists
def user_exists(user_id):
    return db["users"].count_documents({"user_id": user_id}) > 0


# If there are no users, register the first user
if db["users"].count_documents({}) == 0:
    register_user()

# Prompt user for user ID
user_id = input("Enter your user ID: ")


def store_new_user_id():
    choice = input("Do you want to store this new User ID? (y/n): ").lower()
    if choice == "y":
        register_user()
        return True
    elif choice == "n":
        return False
    else:
        print("Invalid input. Please enter 'y' or 'n'.")
        return store_new_user_id()


# If user ID does not exist, ask the user if they want to store it
if not user_exists(user_id):
    print("User ID not found.")
    if not store_new_user_id():
        print("Exiting the program...")
        exit()


def login(user_id):
    attempts = 3
    while attempts > 0:
        password = getpass("Enter master password: ")
        hashed_master_password = db["users"].find_one({"user_id": user_id})[
            "master_password"
        ]
        if bcrypt.checkpw(password.encode(), hashed_master_password):
            print("Login successful")
            return password
        else:
            attempts -= 1
            print("Incorrect password, please try again.")
    print("Too many login attempts, quitting...")
    return None


master_password = login(user_id)
if not master_password:
    exit()


# Connect to user-specific folder of passwords
collection = db["passwords_{}".format(user_id)]


# Function to generate a random password
def generate_random_password():
    length = int(input("Enter the desired password length: "))
    nums = input("Include numbers? (y/n): ").lower() == "y"
    chars = input("Include special characters? (y/n): ").lower() == "y"

    # Generate a random password using the characters in the alphabet
    alphabet = string.ascii_letters
    if nums:
        alphabet += string.digits
    if chars:
        alphabet += string.punctuation
    return "".join(secrets.choice(alphabet) for i in range(length))


# Encrypt the password with AES
def encrypt_password(password, key):
    # If the password is a string, convert it to bytes
    if isinstance(password, str):
        password = password.encode()

    # Create a new AES cipher using the provided key and CBC mode
    cipher = AES.new(key, AES.MODE_CBC)

    # Encrypt the password, padding it to the AES block size
    ciphertext = cipher.encrypt(pad(password, AES.block_size))

    # Return the ciphertext with the initialization vector (IV) prepended
    return cipher.iv + ciphertext


# Decrypt the password with AES
def decrypt_password(ciphertext, key):
    # Extract the initialization vector (IV) from the ciphertext
    iv = ciphertext[: AES.block_size]

    # Create a new AES cipher using the provided key, CBC mode, and IV
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # Decrypt the ciphertext, excluding the IV
    plaintext = cipher.decrypt(ciphertext[AES.block_size :])

    # Unpad the decrypted plaintext and return it
    return unpad(plaintext, AES.block_size)


def store_password(master_password):
    # Get the username and password from the user
    username = input("Enter the login username: ")

    # Prompt user for password or generate a random one
    password_choice = input(
        "Enter 'c' to create a password or 'g' to generate one: "
    ).lower()
    if password_choice == "c":
        password = getpass("Enter the password: ")
    elif password_choice == "g":
        password = generate_random_password()

        # Ask user if they want to print the generated password
        print_choice = input(
            "Would you like to print the generated password? (y/n): "
        ).lower()
        if print_choice == "y":
            print("Generated password: " + password)
        elif print_choice == "n":
            print("Generated password will not be displayed.")
        else:
            print("Invalid input. Generated password will not be displayed.")
    else:
        print("Invalid input. Please try again.")
        return store_password(master_password)

    # Generate a salt and hash the password with bcrypt
    salt = bcrypt.gensalt()

    # Derive a key for AES encryption using PBKDF2
    key = PBKDF2(master_password.encode(), salt, dkLen=32)

    # Encrypt the plaintext password with AES
    encrypted_password = encrypt_password(password, key)

    # Ask the user for a label
    label = input("Enter a label for this login: ")

    # Check if the user entered a label, and prompt again if not
    while not label.strip():
        print("Label is required.")
        label = input("Enter a label for this password: ")

    # Store the encrypted password, salt, username, and label in MongoDB
    document = {
        "username": username,
        "password": Binary(encrypted_password),
        "salt": Binary(salt),
        "label": label,
    }
    result = collection.insert_one(document)

    # Check that the password was stored successfully
    if result.acknowledged:
        print("Password stored successfully.")
    else:
        print("Error: Password not stored. Please try again")


def retrieve_password():
    # Prompt the user for the master password
    password = getpass("Please re-enter the master password: ")

    if password == master_password:
        # Get the password label from the user
        label = input(
            "Enter the label of the password you would like to retrieve: "
        )

        # Find the document that matches the username and label
        result = collection.find_one({"label": label})

        # Check if a matching document was found
        if not result:
            print("Error: Password not found.")
            return

        # Get the encrypted password and salt from the document
        encrypted_password = result["password"]
        salt = result["salt"]

        # Derive the key for AES decryption using PBKDF2
        key = PBKDF2(password.encode(), salt, dkLen=32)

        # Decrypt the password
        plaintext_password = decrypt_password(encrypted_password, key).decode(
            "utf-8"
        )

        # Display the decrypted password using getpass
        print("Decrypted password for label '{}':".format(label))
        _ = getpass(
            prompt="Press enter to retrieve the password, for security it will not be shown on the screen"
        )
        print(
            "\nThe password is in the clipboard, you can paste it where needed."
        )
        pyperclip.copy(plaintext_password)

    else:
        print("Password is incorrect")
        exit()


# Main program loop
def main():
    while True:
        choice = input(
            "Enter 's' to store a password, 'r' to retrieve a password, or 'q' to quit: "
        )
        if choice == "s":
            store_password(master_password)
        elif choice == "r":
            retrieve_password()
        elif choice == "q":
            break
        else:
            print("Error: Invalid input. Please try again.")


if __name__ == "__main__":
    main()
