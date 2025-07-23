**SecurePass: Encrypted Password Manager with 2FA and Strength Evaluation**

SecurePass is a secure terminal-based password manager written in Python. It allows you to store your credentials safely using strong encryption, 2-factor authentication (2FA), password strength evaluation, and automatic vault locking on inactivity.

**FEATURES**

- Encrypted password vault (`vault.enc`) using AES encryption
- Master password stored with bcrypt hashing (`master.hash`)
- Time-based 2FA login using TOTP (`totp.secret`)
- QR code generation for easy 2FA setup with Google Authenticator or Authy
- Password strength scoring and suggestions using `zxcvbn`
- Common password check using Kali’s `rockyou.txt` wordlist
- Auto-locking after 5 minutes of inactivity (resets with each action)
- Add, view, update, delete, and search for stored entries
- Return to menu anytime from within the app

**INSTALLATION INSTRUCTIONS**

1. Clone this repository:
   `git clone https://github.com/zabloudilaATWIT/securepass.git`
   `cd securepass`

4. Create and activate a virtual environment:
    `python3 -m venv venv`
    `source venv/bin/activate`

5. Install required packages:
    `pip install -r requirements.txt`

**FIRST-TIME SETUP (Run Only Once)**

Step 1: Create a master password:
    `python auth.py`

- You'll be prompted to enter a secure master password.
- The password is hashed with bcrypt and stored in 'master.hash'.

Step 2: Set up 2FA:
    `python 2fa.py`

This script will:
- Generate a 2FA secret and store it in 'totp.secret'
- Create a QR code image ('totp_qr.png')

How to use the QR code:
- Open your authenticator app (Google Authenticator or Authy)
- Scan the QR code in 'totp_qr.png'
- Your app will now generate a 6-digit code every 30 seconds

**USING SECUREPASS**

To run the manager:
    `python manager.py`

You'll be asked to:
1. Enter your master password
2. Enter your 6-digit code from your Authenticator app

Main menu options:
    1. Add New Entry
    2. View Vault
    3. Delete Entry
    4. Update Entry
    5. Search Vault
    0. Exit

- You must use strong passwords (score ≥ 75).
- You can update weak passwords directly through the interface.

**SECURITY FILES – DO NOT SHARE**

These contain personal data and must be kept private:
- vault.enc       → your encrypted credentials
- master.hash     → your hashed master password
- totp.secret     → your 2FA secret
- totp_qr.png     → QR image that reveals the secret key

These files are excluded using '.gitignore' to prevent accidental upload.

**RESETTING YOUR SETUP**

To wipe everything and start over:
- `rm vault.enc master.hash totp.secret totp_qr.png`
- `python auth.py`
- `python 2fa.py`



**Reopening SecurePass After Exiting the Terminal**

If you close the terminal or restart your computer, follow these steps to reopen SecurePass:
1. Open a new terminal window
2. Navigate to the project directory
    `cd ~/securepass`
3. Activate the virtual environment
    `source venv/bin/activate`
4. Run the password manager
    `python manager.py` or `python3 manager.py`
5. Log in

You'll be prompted to:
- Enter your master password
- Enter the 6-digit code from your authenticator app (2FA)
  
Make sure these files still exist:
    master.hash
    totp.secret 
    vault.enc      
    venv           
If these are in place, you can reopen SecurePass anytime!

**FOR OTHER USERS**

When someone else clones this project, they will:
- Set their own master password
- Set up their own 2FA
- Store their own credentials

*None of your passwords or secrets are included.*

**SYSTEM REQUIREMENTS**

- Python 3.7 or higher
- Git (optional for cloning)
- Tested on Kali Linux, should work on Linux/macOS/WSL

**DISCLAIMER**

This project, SecurePass, is provided for educational and personal use only.

It is intended to demonstrate concepts related to password management, encryption, authentication, and secure software development. While SecurePass incorporates industry-standard libraries and good security practices, it is not intended for use in high-security or production environments without further auditing, hardening, and testing by security professionals.

The authors of this project do not assume any responsibility for data loss, unauthorized access, or misuse resulting from the use of this software.

By using this project, you acknowledge that:
- You understand it is experimental and for learning purposes
- You are solely responsible for protecting any sensitive data stored with this tool
- You will not hold the authors liable for any issues or damages resulting from its use

**LICENSE**

MIT License – open for personal, academic, and non-commercial use.
