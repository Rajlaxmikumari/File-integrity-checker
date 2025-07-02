import hashlib
import os

def calculate_hash(file_path, algorithm='sha256'):
    """Calculate the hash value of a file using the specified algorithm."""
    hash_algorithm = hashlib.new(algorithm)
    try:
        with open(file_path, 'rb') as file:
            for chunk in iter(lambda: file.read(4096), b""):
                hash_algorithm.update(chunk)
        return hash_algorithm.hexdigest()
    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found.")
        return None

def save_hash(file_path, hash_value, hash_file='file_hashes.txt'):
    """Save the hash value of a file to a hash file."""
    with open(hash_file, 'a') as f:
        f.write(f"{file_path}:{hash_value}\n")

def load_hash(file_path, hash_file='file_hashes.txt'):
    """Load the stored hash value of a file from the hash file."""
    if not os.path.exists(hash_file):
        return None
    with open(hash_file, 'r') as f:
        for line in f:
            stored_file, stored_hash = line.strip().split(':')
            if stored_file == file_path:
                return stored_hash
    return None

def check_file_integrity(file_path, hash_file='file_hashes.txt'):
    """Check the integrity of a file by comparing its current hash with the stored hash."""
    current_hash = calculate_hash(file_path)
    if current_hash is None:
        return

    stored_hash = load_hash(file_path, hash_file)
    if stored_hash is None:
        print(f"No stored hash found for '{file_path}'. Saving current hash.")
        save_hash(file_path, current_hash, hash_file)
    elif current_hash == stored_hash:
        print(f"File '{file_path}' is intact. No changes detected.")
    else:
        print(f"Warning: File '{file_path}' has been modified! Stored hash: {stored_hash}, Current hash: {current_hash}")

def main():
    # Example usage
    file_to_check = 'example.txt'
    check_file_integrity(file_to_check)

if __name__ == '__main__':
    main()
