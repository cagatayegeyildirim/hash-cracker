What is a Hash?
A hash is a transformation of a data set (such as a file or password) into a fixed-length output. This transformation is one-way, meaning it is generally not possible to reverse the hash to retrieve the original data. Hash functions are typically used to verify data integrity, perform encryption, or index data.

Where is it Used?

Encryption: Hash functions are used to securely store passwords. For example, passwords are usually stored in databases as hashed values.

Data Verification: Used to check the integrity of files or data blocks (e.g., to verify that a file has not been corrupted during download).

Data Structures: Used in data structures like hash tables and hash sets for searching and storing data.

What Does a Hash Cracker Do?

A Hash Cracker is a tool designed to find the original data (usually a password) from a hash value. It uses various methods (such as brute force, dictionary attacks, rainbow tables) to reverse-engineer the hash and recover the original data. These tools are commonly used for security research or identifying weak passwords.

Features

Hash Cracking: Solve popular hash algorithms such as MD5, SHA256, bcrypt, argon2.

Multithreading: Use multiple threads for faster cracking.

Rainbow Table Support: Quickly crack hashes using rainbow tables.

Rainbow Table Creation: Create and use your own rainbow tables.

Requirements

•	Python 3.x

•	bcrypt (pip install bcrypt)

•	argon2 (pip install argon2-cffi)

Installation

  -> pip install -r requirements.txt

Usage

```
python hash_cracker.py <hash_to_crack> <algorithm> <wordlist_path> [--threads <num_threads>] [--rainbow] [--create_rainbow]
```
- `<hash_to_crack>`: The hash to crack.
- `<algorithm>`: The hash algorithm used (e.g., md5, sha256, bcrypt, argon2).
- `<wordlist_path>`: The path to the wordlist file.
- `--threads <num_threads>`: Specifies the number of threads for multithreading (default is 4).
- `--rainbow`: Enables cracking using a rainbow table.
- `--create_rainbow`: Creates a rainbow table from the given wordlist file.
- `--rainbow_table`: Specifies the path to the rainbow table file to use.

Example Usage

-> Simple Hash Cracking:

python hash_cracker.py 5f4dcc3b5aa765d61d8327deb882cf99 md5 wordlist.txt

Hash Cracking with Multithreading:

python hash_cracker.py 5f4dcc3b5aa765d61d8327deb882cf99 md5 wordlist.txt --threads 8

Hash Cracking Using Rainbow Table:

python hash_cracker.py 5f4dcc3b5aa765d61d8327deb882cf99 md5 wordlist.txt --rainbow --rainbow_table rainbow_table.txt

Creating a Rainbow Table:

python hash_cracker.py --create_rainbow wordlist.txt md5 rainbow_table.txt

Output

[+] Hash: 5f4dcc3b5aa765d61d8327deb882cf99
[+] Algorithm: md5
[+] Wordlist: wordlist.txt
[+] Password found: password
[+] Elapsed time: 2.45 seconds

If the password is not found:

[!] Password not found.
[+] Elapsed time: 2.45 seconds





