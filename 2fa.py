# 2fa_setup.py
import pyotp
import qrcode

def setup_2fa():
    # Generate a random base32 secret
    secret = pyotp.random_base32()

    # Save secret to file
    with open("totp.secret", "w") as f:
        f.write(secret)

    # Create provisioning URI for Google Authenticator
    uri = pyotp.totp.TOTP(secret).provisioning_uri(name="securepass_user", issuer_name="SecurePass")

    # Generate QR code and save as image
    qr = qrcode.make(uri)
    qr.save("totp_qr.png")

    print("2FA setup complete.")
    print("Scan the QR code in 'totp_qr.png' using Google Authenticator or Authy.")

if __name__ == "__main__":
    setup_2fa()
