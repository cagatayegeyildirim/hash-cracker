import hashlib
import bcrypt
from argon2 import PasswordHasher
import argparse
import time
import threading


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


def create_rainbow_table(wordlist_path, algorithm, output_file):
    try:
        with open(wordlist_path, "r", encoding="utf-8") as wordlist, open(output_file, "w") as output:
            for word in wordlist:
                word = word.strip()
                generated_hash = hashlib.new(algorithm, word.encode()).hexdigest()
                output.write(f"{generated_hash}:{word}\n")
        print(f"[+] Rainbow Table created: {output_file}")
    except FileNotFoundError:
        print(f"[!] Wordlist not found: {wordlist_path}")


def search_rainbow_table(hash_to_crack, rainbow_table_path):
    try:
        with open(rainbow_table_path, "r") as table:
            for line in table:
                stored_hash, password = line.strip().split(":")
                if stored_hash == hash_to_crack:
                    return password
        return None
    except FileNotFoundError:
        print(f"[!] Rainbow Table file not found: {rainbow_table_path}")


def worker(hash_to_crack, algorithm, wordlist_chunk, result):
    for word in wordlist_chunk:
        word = word.strip()
        if compare_hash(word, hash_to_crack, algorithm):
            result.append(word)
            break


def multithreaded_crack(hash_to_crack, algorithm, wordlist_path, num_threads=4):
    try:
        with open(wordlist_path, "r", encoding="utf-8") as wordlist:
            words = wordlist.readlines()
        
        chunk_size = len(words) // num_threads
        threads = []
        result = []
        

        for i in range(num_threads):
            chunk = words[i * chunk_size:(i + 1) * chunk_size]
            thread = threading.Thread(target=worker, args=(hash_to_crack, algorithm, chunk, result))
            threads.append(thread)
            thread.start()
        

        for thread in threads:
            thread.join()

        return result[0] if result else None
    except Exception as e:
        print(f"[!] Hata: {e}")
        return None


def get_arguments():
    parser = argparse.ArgumentParser(description="Hash Cracker")
    parser.add_argument("hash", help="Hash to Crack")
    parser.add_argument("algorithm", help="Algorithm used (md5, sha256, bcrypt, argon2, etc.)")
    parser.add_argument("wordlist", help="Path to the wordlist file")
    parser.add_argument("--threads", type=int, default=4, help="Number of threads for multithreading (default: 4)")
    parser.add_argument("--rainbow", action="store_true", help="Use Rainbow Table for hash cracking")
    parser.add_argument("--create_rainbow", action="store_true", help="Create a Rainbow Table from wordlist")
    parser.add_argument("--rainbow_table", help="Path to the Rainbow Table")
    return parser.parse_args()


if __name__ == "__main__":
    args = get_arguments()
    start_time = time.time()

    print(f"[+] Hash: {args.hash}")
    print(f"[+] Algorithm: {args.algorithm}")
    print(f"[+] Wordlist: {args.wordlist}")


    if args.create_rainbow:
        create_rainbow_table(args.wordlist, args.algorithm, "rainbow_table.txt")
    elif args.rainbow and args.rainbow_table:
        result = search_rainbow_table(args.hash, args.rainbow_table)
        if result:
            print(f"[+] Password found in Rainbow Table: {result}")
        else:
            print("[!] Password not found in Rainbow Table.")
    else:
        if args.threads > 1:
            result = multithreaded_crack(args.hash, args.algorithm, args.wordlist, args.threads)
        else:
            result = crack_hash(args.hash, args.algorithm, args.wordlist)

        if result:
            print(f"[+] Password found: {result}")
        else:
            print("[!] Password not found.")
    
    end_time = time.time()
    print(f"[+] Elapsed time: {end_time - start_time:.2f} seconds")
