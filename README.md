# SecretScanner

Find hardcoded credentials in code repositories.

## Installation

```bash
git clone https://github.com/00x127/SecretScanner
cd SecretScanner
chmod +x secretscanner.py
```

Python 3.8+ required. No dependencies.

## Usage

```bash
# Scan directory
python3 secretscanner.py scan /path/to/project

# Scan GitHub repo
python3 secretscanner.py url https://github.com/user/repo

# Include git history
python3 secretscanner.py url https://github.com/user/repo --history

# Save results
python3 secretscanner.py scan . -o report.json

# Verbose mode
python3 secretscanner.py scan . -v
```

## What It Finds

70+ credential patterns including:
- AWS keys and secrets
- GitHub/GitLab tokens
- API keys from major services
- Database connection strings
- Private SSH/PGP keys
- OAuth secrets
- Stripe API keys

## Options

```
scan              Scan local directory
url               Clone and scan repository
--history         Include git commit history
-o FILE           Export to JSON
-v                Verbose output
```
