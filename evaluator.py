from zxcvbn import zxcvbn
import os

def evaluate_password(password):
    result = zxcvbn(password)
    
    #Convert zxcvbn score (0–4) to 1–100 scale
    score = result['score'] * 25 + 1
    print(f"\nPassword Score: {min(score, 100)} / 100")

    #Feedback
    feedback = result['feedback']
    if feedback['warning']:
        print("Warning:", feedback['warning'])
    if feedback['suggestions']:
        print("Suggestions:")
        for suggestion in feedback['suggestions']:
            print("   -", suggestion)

    #Crack time estimate (using bcrypt 10k guesses/sec)
    crack_time = result['crack_times_display']['offline_slow_hashing_1e4_per_second']
    print("Estimated Crack Time:", crack_time)

    #Check against rockyou.txt
    check_against_rockyou(password)

def check_against_rockyou(password):
    rockyou_path = "/usr/share/wordlists/rockyou.txt"
    
    if not os.path.exists(rockyou_path):
        print("rockyou.txt not found. Skipping breached password check.")
        return

    try:
        with open(rockyou_path, "r", encoding="latin-1") as file:
            for line in file:
                if line.strip() == password:
                    print("This password is found in a list of common passwords! It is extremely unsafe.")
                    return
        print("This password does not appear in a list of common passwords.")
    except Exception as e:
        print(f"Error checking rockyou.txt: {e}")

#Run interactively
if __name__ == "__main__":
    pw = input("Enter a password to evaluate: ")
    evaluate_password(pw)
