import secrets
import string
import os
from cryptography.fernet import Fernet

def generate_key(key_file="key.key"):
    if not os.path.exists(key_file):
        key = Fernet.generate_key()
        with open(key_file, "wb") as file:
            file.write(key)

def load_key(key_file="key.key"):
    if os.path.exists(key_file):
        with open(key_file, "rb") as file:
            return file.read()
    else:
        raise FileNotFoundError("Encryption key not found. Run the program again to generate it.")

def encrypt_data(data, key):
    fernet = Fernet(key)
    return fernet.encrypt(data.encode())

def decrypt_data(data, key):
    fernet = Fernet(key)
    return fernet.decrypt(data).decode()

def generate_password(length=16, use_letters=True, use_digits=True, use_punctuation=True):
    char_pool = ''
    if use_letters:
        char_pool += string.ascii_letters
    if use_digits:
        char_pool += string.digits
    if use_punctuation:
        char_pool += string.punctuation
    if not char_pool:
        raise ValueError("No character types selected. Please enable at least one character type.")
    return ''.join(secrets.choice(char_pool) for _ in range(length))

def assess_password_strength(password):
    length = len(password)
    has_letters = any(char.isalpha() for char in password)
    has_digits = any(char.isdigit() for char in password)
    has_punctuation = any(char in string.punctuation for char in password)

    score = sum([has_letters, has_digits, has_punctuation])
    if length >= 16 and score == 3:
        return "Strong"
    elif length >= 12 and score >= 2:
        return "average"
    else:
        return "Weak"


def save_password_to_file(password, key, filename="passwords_encrypted.txt"):
    encrypted_password = encrypt_data(password, key)
    with open(filename, "ab") as file:
        file.write(encrypted_password + b"\n")

def view_passwords(key, filename="passwords_encrypted.txt"):
    if os.path.exists(filename):
        with open(filename, "rb") as file:
            lines = file.readlines()
            print("\nStored Passwords:")
            for line in lines:
                print(decrypt_data(line.strip(), key))
    else:
        print("No stored passwords found.")


def main():
    generate_key()  
    key = load_key() 

    print("KeyCrafter a password generator tool")
    try:
        length = int(input("Enter password length (default is 16): ") or 16)
        use_letters = input("Include letters? (y/n, default is y): ").lower() in ["y", "yes", ""]
        use_digits = input("Include digits? (y/n, default is y): ").lower() in ["y", "yes", ""]
        use_punctuation = input("Include punctuation? (y/n, default is y): ").lower() in ["y", "yes", ""]

        password = generate_password(length, use_letters, use_digits, use_punctuation)
        strength = assess_password_strength(password)

        print(f"\nGenerated Password: {password}")
        print(f"Password Strength: {strength}")

        save_password = input("Save this password to an encrypted file? (y/n, default is n): ").lower() in ["y", "yes"]
        if save_password:
            save_password_to_file(password, key)
            print(f"Password saved to {os.path.abspath('passwords_encrypted.txt')}")

        view_stored = input("View stored passwords? (y/n, default is n): ").lower() in ["y", "yes"]
        if view_stored:
            view_passwords(key)

    except ValueError as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
