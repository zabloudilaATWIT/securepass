import bcrypt
import pyotp

#Step 1: Create and store master password
def create_master_password():
    password = input("🔑Set a master password: ").encode()

    #Hash the password using bcrypt
    hashed = bcrypt.hashpw(password, bcrypt.gensalt())

    #Save the hash to a file
    with open("master.hash", "wb") as f:
        f.write(hashed)

    print("Master password created and securely stored.")

#Step 2: Verify master password during login
def verify_master_password():
    password = input("🔑Enter your master password: ").encode()

    try:
        with open("master.hash", "rb") as f:
            stored_hash = f.read()
    except FileNotFoundError:
        print("⚠️Master password not set up yet.")
        return False

    if bcrypt.checkpw(password, stored_hash):
        print("🔑Master password verified.")
        return True
    else:
        print("🚨Incorrect master password.")
        return False

#Step 3: Verify 2FA code
def verify_2fa():
    try:
        with open("totp.secret", "r") as f:
            secret = f.read().strip()
    except FileNotFoundError:
        print("⚠️2FA is not set up yet. Run 2fa_setup.py first.")
        return False

    totp = pyotp.TOTP(secret)
    code = input("🛠️Enter 6-digit code from your Authenticator app: ")

    if totp.verify(code):
        print("✅️2FA verification successful.")
        return True
    else:
        print("❌Invalid 2FA code.")
        return False

#Run interactively
if __name__ == "__main__":
    print("1. Create Master Password")
    print("2. Verify Master Password + 2FA")
    choice = input("Choose (1 or 2): ")

    if choice == "1":
        create_master_password()
    elif choice == "2":
        if verify_master_password():
            if verify_2fa():
                print("✅Access to vault granted.")
            else:
                print("❌2FA failed. Access denied.")
    else:
        print("⚠️Invalid choice.")
