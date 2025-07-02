import hashlib
import os
import json
from datetime import datetime

def calculate_file_hash(filepath, algorithm='sha256', buffer_size=65536):
    """
    Calculate the hash of a file using the specified algorithm.
    
    Args:
        filepath (str): Path to the file to hash
        algorithm (str): Hash algorithm to use (default: sha256)
        buffer_size (int): Buffer size for reading the file (default: 64KB)
    
    Returns:
        str: The hexadecimal digest of the file's hash
    """
    hash_func = hashlib.new(algorithm)
    
    try:
        with open(filepath, 'rb') as f:
            while True:
                data = f.read(buffer_size)
                if not data:
                    break
                hash_func.update(data)
    except IOError as e:
        print(f"Error reading file {filepath}: {e}")
        return None
    
    return hash_func.hexdigest()

def scan_directory(directory, algorithm='sha256', extensions=None):
    """
    Scan a directory and calculate hashes for all files.
    
    Args:
        directory (str): Path to the directory to scan
        algorithm (str): Hash algorithm to use (default: sha256)
        extensions (list): List of file extensions to include (None for all files)
    
    Returns:
        dict: Dictionary mapping file paths to their hashes
    """
    file_hashes = {}
    
    for root, _, files in os.walk(directory):
        for filename in files:
            if extensions:
                if not any(filename.lower().endswith(ext) for ext in extensions):
                    continue
            
            filepath = os.path.join(root, filename)
            file_hash = calculate_file_hash(filepath, algorithm)
            
            if file_hash:
                # Store relative path if possible
                try:
                    rel_path = os.path.relpath(filepath, directory)
                except ValueError:
                    rel_path = filepath
                
                file_hashes[rel_path] = file_hash
    
    return file_hashes

def save_baseline(directory, output_file, algorithm='sha256', extensions=None):
    """
    Create and save a baseline of file hashes for a directory.
    
    Args:
        directory (str): Path to the directory to scan
        output_file (str): Path to save the baseline JSON file
        algorithm (str): Hash algorithm to use (default: sha256)
        extensions (list): List of file extensions to include (None for all files)
    """
    file_hashes = scan_directory(directory, algorithm, extensions)
    
    baseline = {
        'timestamp': datetime.now().isoformat(),
        'algorithm': algorithm,
        'directory': os.path.abspath(directory),
        'files': file_hashes
    }
    
    try:
        with open(output_file, 'w') as f:
            json.dump(baseline, f, indent=2)
        print(f"Baseline saved to {output_file} with {len(file_hashes)} files.")
    except IOError as e:
        print(f"Error saving baseline: {e}")

def load_baseline(baseline_file):
    """
    Load a previously saved baseline file.
    
    Args:
        baseline_file (str): Path to the baseline JSON file
    
    Returns:
        dict: The loaded baseline data
    """
    try:
        with open(baseline_file, 'r') as f:
            return json.load(f)
    except (IOError, json.JSONDecodeError) as e:
        print(f"Error loading baseline file: {e}")
        return None

def compare_with_baseline(directory, baseline_file):
    """
    Compare current files with a saved baseline.
    
    Args:
        directory (str): Path to the directory to scan
        baseline_file (str): Path to the baseline JSON file
    
    Returns:
        dict: Comparison results showing added, modified, and removed files
    """
    baseline = load_baseline(baseline_file)
    if not baseline:
        return None
    
    current_hashes = scan_directory(directory, baseline['algorithm'])
    
    baseline_files = set(baseline['files'].keys())
    current_files = set(current_hashes.keys())
    
    results = {
        'added': [],
        'removed': [],
        'modified': [],
        'unchanged': []
    }
    
    # Check for added files
    for file in current_files - baseline_files:
        results['added'].append(file)
    
    # Check for removed files
    for file in baseline_files - current_files:
        results['removed'].append(file)
    
    # Check for modified files
    common_files = current_files & baseline_files
    for file in common_files:
        if current_hashes[file] == baseline['files'][file]:
            results['unchanged'].append(file)
        else:
            results['modified'].append(file)
    
    return results

def print_comparison_results(results):
    """
    Print the comparison results in a readable format.
    """
    if not results:
        print("No results to display.")
        return
    
    print("\nFile Integrity Check Results:")
    print(f"Added files ({len(results['added'])}):")
    for file in results['added']:
        print(f"  + {file}")
    
    print(f"\nRemoved files ({len(results['removed'])}):")
    for file in results['removed']:
        print(f"  - {file}")
    
    print(f"\nModified files ({len(results['modified'])}):")
    for file in results['modified']:
        print(f"  * {file}")
    
    print(f"\nUnchanged files ({len(results['unchanged'])}):")
    if len(results['unchanged']) > 10:
        print("  (First 10 shown)")
        for file in list(results['unchanged'])[:10]:
            print(f"  {file}")
        print("  ...")
    else:
        for file in results['unchanged']:
            print(f"  {file}")
    
    print("\nSummary:")
    print(f"Total files added: {len(results['added'])}")
    print(f"Total files removed: {len(results['removed'])}")
    print(f"Total files modified: {len(results['modified'])}")
    print(f"Total files unchanged: {len(results['unchanged'])}")

def main():
    import argparse
    
    parser = argparse.ArgumentParser(
        description="File Integrity Checker - Monitor changes in files by comparing hash values."
    )
    subparsers = parser.add_subparsers(dest='command', required=True)
    
    # Create baseline command
    baseline_parser = subparsers.add_parser('create', help='Create a new baseline')
    baseline_parser.add_argument('directory', help='Directory to scan')
    baseline_parser.add_argument('-o', '--output', default='baseline.json',
                               help='Output baseline file (default: baseline.json)')
    baseline_parser.add_argument('-a', '--algorithm', default='sha256',
                               choices=['md5', 'sha1', 'sha256', 'sha512'],
                               help='Hash algorithm (default: sha256)')
    baseline_parser.add_argument('-e', '--extensions', nargs='+',
                               help='File extensions to include (all files if not specified)')
    
    # Compare command
    compare_parser = subparsers.add_parser('compare', help='Compare with a baseline')
    compare_parser.add_argument('directory', help='Directory to scan')
    compare_parser.add_argument('baseline', help='Baseline file to compare against')
    
    args = parser.parse_args()
    
    if args.command == 'create':
        save_baseline(
            args.directory,
            args.output,
            algorithm=args.algorithm,
            extensions=args.extensions
        )
    elif args.command == 'compare':
        results = compare_with_baseline(args.directory, args.baseline)
        print_comparison_results(results)

if __name__ == '__main__':
    main()
