import bcrypt
import json
import os
import base64
import hashlib
import threading
from cryptography.fernet import Fernet
from getpass import getpass
from zxcvbn import zxcvbn
import pyotp

#Global Variables
inactivity_timer = None
INACTIVITY_TIMEOUT = 300  # 5 minutes


#Timer and Security

def auto_logout():
    print("\nInactivity timeout reached. Vault locked.")
    os._exit(0)

def reset_timer():
    global inactivity_timer
    if inactivity_timer:
        inactivity_timer.cancel()
    inactivity_timer = threading.Timer(INACTIVITY_TIMEOUT, auto_logout)
    inactivity_timer.start()

def get_encryption_key(master_password):
    hashed = hashlib.sha256(master_password.encode()).digest()
    return base64.urlsafe_b64encode(hashed)

def verify_master():
    if not os.path.exists("master.hash"):
        print("Master password not set up.")
        return None

    master = getpass("Enter master password: ").encode()
    with open("master.hash", "rb") as f:
        stored = f.read()

    if bcrypt.checkpw(master, stored):
        print("Master password verified.")
        return master.decode()
    else:
        print("Incorrect master password.")
        return None

def verify_2fa():
    try:
        with open("totp.secret", "r") as f:
            secret = f.read().strip()
    except FileNotFoundError:
        print("2FA not set up.")
        return False

    totp = pyotp.TOTP(secret)
    code = input("Enter 6-digit code from your Authenticator app: ")
    if totp.verify(code):
        print("2FA passed.")
        return True
    else:
        print("Invalid 2FA code.")
        return False

def evaluate_strength(password):
    result = zxcvbn(password)
    score = result['score'] * 25 + 1
    print(f"\nPassword Score: {min(score, 100)} / 100")
    if result['feedback']['warning']:
        print(result['feedback']['warning'])
    for tip in result['feedback']['suggestions']:
        print(tip)
    print("Crack Time:", result['crack_times_display']['offline_slow_hashing_1e4_per_second'])

    return score >= 75


#Vault Management

def load_vault(file, key):
    if not os.path.exists(file):
        return []

    f = Fernet(key)
    try:
        with open(file, "rb") as vault:
            decrypted = f.decrypt(vault.read())
            return json.loads(decrypted.decode())
    except Exception as e:
        print("Could not decrypt vault:", e)
        return []

def save_vault(file, data, key):
    f = Fernet(key)
    encrypted = f.encrypt(json.dumps(data).encode())
    with open(file, "wb") as vault:
        vault.write(encrypted)


#Entry Actions

def add_entry(vault_file, key, vault_data):
    account = input("Account name: ")
    username = input("Username: ")

    while True:
        password = getpass("Password: ")
        if evaluate_strength(password):
            break
        print("Password not strong enough. Please try again.")

    vault_data.append({
        "account": account,
        "username": username,
        "password": password
    })

    save_vault(vault_file, vault_data, key)
    print("Entry added.")

def view_entries(vault_data):
    if not vault_data:
        print("Vault is empty.")
        return
    print("\nStored Accounts:")
    for i, entry in enumerate(vault_data, start=1):
        print(f"{i}. {entry['account']} → {entry['username']} | {entry['password']}")

def delete_entry(vault_file, key, vault_data):
    view_entries(vault_data)
    index = int(input("Enter entry number to delete: ")) - 1
    if 0 <= index < len(vault_data):
        removed = vault_data.pop(index)
        save_vault(vault_file, vault_data, key)
        print(f"🗑️ Deleted {removed['account']}")
    else:
        print("Invalid entry number.")

def update_entry(vault_file, key, vault_data):
    view_entries(vault_data)
    index = int(input("Enter entry number to update: ")) - 1
    if 0 <= index < len(vault_data):
        print("Leave blank to keep current values.")
        account = input(f"Account ({vault_data[index]['account']}): ") or vault_data[index]['account']
        username = input(f"Username ({vault_data[index]['username']}): ") or vault_data[index]['username']
        current_pw = vault_data[index]['password']

        password = getpass("New password (leave blank to keep current): ")
        if password:
            while not evaluate_strength(password):
                print("New password is not strong enough.")
                password = getpass("Please enter a stronger password: ")
        else:
            print("\n🔍 Evaluating current password strength...")
            if not evaluate_strength(current_pw):
                print("Your old password is weak. You must update it.")
                while True:
                    password = getpass("Enter a new stronger password: ")
                    if evaluate_strength(password):
                        break
            else:
                password = current_pw

        vault_data[index] = {"account": account, "username": username, "password": password}
        save_vault(vault_file, vault_data, key)
        print(f"Updated {account}")
    else:
        print("Invalid entry number.")

def search_entries(vault_data):
    query = input("Enter account name to search: ").lower()
    results = [entry for entry in vault_data if query in entry['account'].lower()]
    
    if results:
        print("\n🔎 Matching Entries:")
        for entry in results:
            print(f"{entry['account']}")
            print(f"   Username: {entry['username']}")
            print(f"   Password: {entry['password']}")
    else:
        print("No matching accounts found.")


#Main

def main():
    vault_file = "vault.enc"

    master_password = verify_master()
    if not master_password:
        return
    if not verify_2fa():
        return

    reset_timer()
    key = get_encryption_key(master_password)
    vault_data = load_vault(vault_file, key)

    while True:
        print("\nSecurePass Password Manager")
        print("1. Add New Entry")
        print("2. View Vault")
        print("3. Delete Entry")
        print("4. Update Entry")
        print("5. Search Vault")
        print("0. Exit")
        choice = input("Choose an option: ")

        if choice == "1":
            add_entry(vault_file, key, vault_data)
        elif choice == "2":
            view_entries(vault_data)
        elif choice == "3":
            delete_entry(vault_file, key, vault_data)
        elif choice == "4":
            update_entry(vault_file, key, vault_data)
        elif choice == "5":
            search_entries(vault_data)
        elif choice == "0":
            print("Exiting and locking vault. Goodbye.")
            os._exit(0)
        else:
            print("❌ Invalid choice.")

        reset_timer()


if __name__ == "__main__":
    main()
