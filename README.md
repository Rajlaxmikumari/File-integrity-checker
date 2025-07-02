# 🔍 File Integrity Checker

A Python tool to monitor file changes using cryptographic hashing (SHA-256/MD5). Detects unauthorized modifications by comparing file hashes against a baseline.

## 🚀 Features
- Create baselines of file hashes.
- Compare directories to detect added/modified/deleted files.
- Supports SHA-256, SHA-1, and MD5 algorithms.

## ⚡ Quick Start
```bash
# Install (no dependencies needed)
git clone https://github.com/yourusername/file-integrity-checker.git

# Create a baseline
python file_checker.py create /path/to/folder -o baseline.json

# Compare later
python file_checker.py compare /path/to/folder baseline.json
