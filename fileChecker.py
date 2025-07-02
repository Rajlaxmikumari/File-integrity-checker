import os
import hashlib

def hash_file(file_path, algorithm='sha256'):
    hash_func = hashlib.new(algorithm)
    with open(file_path, 'rb') as f:
        while chunk := f.read(4096):
            hash_func.update(chunk)
    return hash_func.hexdigest()

def check_file_integrity(original_hash, file_path):
    current_hash = hash_file(file_path)
    if original_hash == current_hash:
        print(f"[+] File {file_path} is intact.")
    else:
        print(f"[-] File {file_path} has been modified!")

if __name__ == "__main__":
    file_path = input("Enter the file path to check: ")
    original_hash = hash_file(file_path)
    print(f"Original file hash: {original_hash}")
    
    input("Press Enter after modifying the file to check integrity again...")
    check_file_integrity(original_hash, file_path)