import hashlib
import bcrypt
from argon2 import PasswordHasher
import argparse
import time

def generate_hash(word, algorithm):
    if algorithm in hashlib.algorithms_guaranteed:
        return hashlib.new(algorithm, word.encode()).hexdigest()
    elif algorithm == "bcrypt":
        return bcrypt.hashpw(word.encode(), bcrypt.gensalt()).decode()
    elif algorithm == "argon2":
        ph = PasswordHasher()
        return ph.hash(word)
    else:
        raise ValueError(f"Unsupported Algorithm: {algorithm}")
    


def compare_hash(word, hash_to_crack, algorithm):
    try:
        if algorithm in hashlib.algorithms_guaranteed:
            return generate_hash(word, algorithm) == hash_to_crack
        elif algorithm == "bcrypt":
            return bcrypt.checkpw(word.encode(), hash_to_crack.encode())
        elif algorithm == "argon2":
            ph = PasswordHasher()
            try:
                ph.verify(hash_to_crack, word)
                return True
            except Exception:
                return False
    except Exception as e:
        print(f"[!] Error: {e}")
    return False


def crack_hash(hash_to_crack, algorithm, wordlist_path):
    try:
        with open(wordlist_path, "r", encoding="utf-8") as wordlist:
            for word in wordlist:
                word = word.strip()
                if compare_hash(word, hash_to_crack, algorithm):
                    return word
        return None
    except FileNotFoundError:
        print(f"[!] Wordlist file not found: {wordlist_path}")
        return None
    

def get_arguments():
    parser = argparse.ArgumentParser(description="Hash Cracker \n // Example Usage : python hash_cracker.py 5f4dcc3b5aa765d61d8327deb882cf99 md5 plaintext.txt")
    parser.add_argument("hash", help="Hash to Crack")
    parser.add_argument("algorithm", help="Algorithm used (md5, sha256, bcrypt, argon2, etc.)")
    parser.add_argument("wordlist", help="Path to the wordlist file")
    return parser.parse_args()




if __name__ == "__main__":
    args = get_arguments()
    start_time = time.time()

    print(f"[+] Hash: {args.hash}")
    print(f"[+] Algorithm: {args.algorithm}")
    print(f"[+] Wordlist: {args.wordlist}")

    result = crack_hash(args.hash, args.algorithm, args.wordlist)
    end_time = time.time()

    if result:
        print(f"[+] Password found: {result}")
    else:
        print("[!] Password not found.")

    print(f"[+] Elapsed time: {end_time - start_time:.2f} second")
