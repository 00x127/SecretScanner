import os
import re
import math
from pathlib import Path

def calc_entropy(text):
    if not text or len(text) == 0:
        return 0

    entropy_val = 0
    for char_code in range(256):
        try:
            occurrences = text.count(chr(char_code))
            if occurrences > 0:
                probability = float(occurrences) / len(text)
                entropy_val += - probability * math.log2(probability)
        except:
            continue
    return entropy_val

def format_file_size(size_bytes):
    """Format file size in human readable format"""
    if size_bytes == 0:
        return "0B"
    
    size_names = ["B", "KB", "MB", "GB", "TB"]
    i = 0
    while size_bytes >= 1024 and i < len(size_names) - 1:
        size_bytes /= 1024.0
        i += 1
    
    return f"{size_bytes:.1f}{size_names[i]}"

def check_if_binary(file_path):
    try:
        with open(file_path, 'rb') as file:
            sample = file.read(8192)
            if not sample:
                return False

            null_bytes = sample.count(b'\x00')
            if null_bytes > len(sample) * 0.3:
                return True

            printable_chars = bytearray({7,8,9,10,12,13,27} | set(range(0x20, 0x100)) - {0x7f})
            non_printable = sum(1 for b in sample if b not in printable_chars)
            if non_printable > len(sample) * 0.3:
                return True

        return False
    except:
        return True

def looks_like_test_data(secret_value, line_text):
    test_indicators = [
        'example', 'sample', 'test', 'dummy', 'fake', 'todo', 'fixme',
        'placeholder', 'changeme', 'your-', 'my-', 'lorem', 'ipsum',
        'EXAMPLE', 'REPLACE', 'INSERT', 'UPDATE', 'SELECT', 'DELETE',
        '${', 'process.env', 'config.', 'settings.', 'os.getenv',
        '<your', '<my', 'TODO:', 'FIXME:', '***', 'xxxxx', 'xxxx',
        'aaaa', 'bbbb', 'cccc', 'dddd', 'eeee', 'ffff', '1111',
        '2222', '3333', '4444', '5555', '6666', '7777', '8888',
        '9999', '0000', 'null', 'None', 'undefined', 'false', 'true'
    ]

    lower_secret = secret_value.lower()
    lower_line = line_text.lower()

    for indicator in test_indicators:
        if indicator.lower() in lower_secret or indicator.lower() in lower_line:
            return True

    if secret_value.count('x') > len(secret_value) * 0.5:
        return True

    if secret_value.count('*') > 5:
        return True

    if secret_value.count('0') == len(secret_value) or secret_value.count('1') == len(secret_value):
        return True

    if re.match(r'^[0-9]+$', secret_value) and len(secret_value) < 16:
        return True

    # Check for repeated patterns
    if len(secret_value) >= 4:
        for i in range(4, len(secret_value)//2 + 1):
            pattern = secret_value[:i]
            if pattern * (len(secret_value)//i) == secret_value[:i*(len(secret_value)//i)]:
                return True

    return False

def extract_match_value(regex_match):
    try:
        for group_idx in range(regex_match.lastindex or 0, 0, -1):
            group_value = regex_match.group(group_idx)
            if group_value and len(group_value) > 5:
                return group_value
        return regex_match.group(0)
    except:
        return regex_match.group(0)

def is_high_entropy_string(text, threshold=3.5):
    """Check if a string has high entropy (likely a secret)"""
    return calc_entropy(text) >= threshold

def sanitize_filename(filename):
    """Sanitize filename for safe file operations"""
    import re
    # Remove invalid characters
    sanitized = re.sub(r'[<>:"/\\|?*]', '_', filename)
    # Remove control characters
    sanitized = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', sanitized)
    # Limit length
    return sanitized[:255]

def get_file_language(file_path):
    """Determine programming language from file extension"""
    ext = Path(file_path).suffix.lower()
    language_map = {
        '.py': 'Python',
        '.js': 'JavaScript',
        '.ts': 'TypeScript',
        '.java': 'Java',
        '.cpp': 'C++',
        '.c': 'C',
        '.cs': 'C#',
        '.php': 'PHP',
        '.rb': 'Ruby',
        '.go': 'Go',
        '.rs': 'Rust',
        '.swift': 'Swift',
        '.kt': 'Kotlin',
        '.scala': 'Scala',
        '.sh': 'Shell',
        '.bash': 'Shell',
        '.zsh': 'Shell',
        '.fish': 'Shell',
        '.ps1': 'PowerShell',
        '.bat': 'Batch',
        '.cmd': 'Batch',
        '.sql': 'SQL',
        '.html': 'HTML',
        '.css': 'CSS',
        '.scss': 'SCSS',
        '.sass': 'SASS',
        '.less': 'LESS',
        '.xml': 'XML',
        '.yaml': 'YAML',
        '.yml': 'YAML',
        '.json': 'JSON',
        '.toml': 'TOML',
        '.ini': 'INI',
        '.cfg': 'Config',
        '.conf': 'Config',
        '.dockerfile': 'Docker',
        '.md': 'Markdown',
        '.tex': 'LaTeX',
        '.r': 'R',
        '.m': 'MATLAB/Octave',
        '.pl': 'Perl',
        '.lua': 'Lua',
        '.vim': 'Vim',
        '.erl': 'Erlang',
        '.ex': 'Elixir',
        '.exs': 'Elixir',
        '.elm': 'Elm',
        '.hs': 'Haskell',
        '.ml': 'OCaml',
        '.fs': 'F#',
        '.dart': 'Dart',
        '.nim': 'Nim',
        '.zig': 'Zig',
        '.v': 'V',
        '.ad': 'Ada',
        '.adb': 'Ada',
        '.ads': 'Ada',
        '.asm': 'Assembly',
        '.s': 'Assembly',
        '.nasm': 'Assembly',
        '.yasm': 'Assembly'
    }
    return language_map.get(ext, 'Unknown')
