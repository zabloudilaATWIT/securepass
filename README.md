git clone https://github.com/zabloudilaATWIT/securepass.git
cd securepass

python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Set up your own master password and 2FA
python auth.py
python 2fa_setup.py

# Start the app
python manager.py
