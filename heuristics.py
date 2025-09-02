import math
import re
import pefile

# Heuristic 1: Suspicious Windows API calls
suspicious_apis = [
    "CreateRemoteThread", "SetWindowsHookEx", "GetAsyncKeyState", 
    "WriteProcessMemory", "ReadProcessMemory", "VirtualAllocEx"
]

# Heuristic 2: Suspicious Python imports or functions
suspicious_python = [
    "pynput", "os.system", "eval", "exec", "ctypes.windll", "keyboard", "subprocess"
]

def has_suspicious_apis(content):
    for keyword in suspicious_apis:
        if keyword.lower() in content:
            return True, keyword
    return False, None

def has_suspicious_python(content):
    for keyword in suspicious_python:
        if keyword.lower() in content:
            return True, keyword
    return False, None

# Heuristic 3: Entropy check (high entropy = possible obfuscation/packing)
def calculate_entropy(data):
    if not data:
        return 0.0
    entropy = 0
    byte_counts = [0] * 256
    for byte in data:
        byte_counts[byte] += 1
    for count in byte_counts:
        if count == 0:
            continue
        p = count / len(data)
        entropy -= p * math.log2(p)
    return entropy

def analyze_pe_structure(filepath):
    try:
        pe = pefile.PE(filepath)
    except pefile.PEFormatError:
        return {"packed": False, "suspicious_imports": []}

    # Heuristic 1: Check for suspicious imports
    suspicious_imports = []
    suspicious_keywords = [
        "CreateRemoteThread", "SetWindowsHookEx", "WriteProcessMemory",
        "ReadProcessMemory", "VirtualAllocEx", "GetAsyncKeyState", "LoadLibraryA"
    ]

    try:
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                if imp.name:
                    name = imp.name.decode(errors="ignore")
                    if name in suspicious_keywords:
                        suspicious_imports.append(name)
    except AttributeError:
        pass

    # Heuristic 2: Look for UPX packing (common obfuscation)
    packed = any(section.Name.strip(b"\x00").lower().startswith(b'upx') for section in pe.sections)

    return {
        "packed": packed,
        "suspicious_imports": suspicious_imports
    }
