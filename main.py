import os
import sys
import hashlib
import binary2strings as b2s
import re
import json

def info():
    global Fname, sz, tp
    if len(sys.argv) > 1:
        Fname = sys.argv[1]
        sz = os.path.getsize(Fname)  # Size in bytes cuz too lazy to make it into mb or kb
        tp = os.path.splitext(Fname)[1]
    else:
        print("WHERE DA FILE AT")
        exit()

def calculate_hash(file_path, algorithm='sha256'):
    hash_func = hashlib.md5() if algorithm == 'md5' else hashlib.sha256()
    with open(file_path, 'rb') as file:
        while chunk := file.read(8192):
            hash_func.update(chunk)
    return hash_func.hexdigest()

def extract_strings():
    global found_iocs, all_strings
    found_iocs = set()
    all_strings = set()

    with open(Fname, "rb") as f:
        data = f.read()

    urls_patterns = [
        r"http[s]?://[^\s'\"<>]+",
        r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b",
        r"\b(?:[a-z0-9-]+\.)+[a-z]{2,6}\b"
    ]

    invalid_ips = {"0.0.0.0", "127.0.0.1", "1.1.1.1"}

    for (string, type, span, is_interesting) in b2s.extract_all_strings(data):
        decoded = string.decode("utf-8", errors="ignore") if isinstance(string, bytes) else string
        all_strings.add(decoded)

        for pattern in urls_patterns:
            for match in re.findall(pattern, decoded):
                if match not in invalid_ips:
                    found_iocs.add(match)

def susapi():
    global found_apis, found_keywords, found_urls
    suspicious_apis = [
        "CreateRemoteThread",
        "WriteProcessMemory",
        "VirtualAllocEx",
        "WinExec",
        "ShellExecute",
        "InternetOpen",
        "InternetConnect",
        "URLDownloadToFile",
        "LoadLibrary",
    ]

    suspicious_keywords = [
        "cmd.exe", "powershell", "regedit", "vssadmin",
        "createobject", "wscript", "shell.application"
    ]

    urls_patterns = [
        r"http[s]?://[^\s'\"<>]+",       
        r"\b\d{1,3}(?:\.\d{1,3}){3}\b"  
    ]

    with open(Fname, "rb") as i:
        data = i.read()

    found_apis = set()
    found_keywords = set()
    found_urls = set()

    for (string, type, span, is_interesting) in b2s.extract_all_strings(data):
        decoded = string.decode("utf-8", errors="ignore") if isinstance(string, bytes) else string
        decoded_lower = decoded.lower()

        for api in suspicious_apis:
            if api in decoded and api not in found_apis:
                found_apis.add(api)

        for kw in suspicious_keywords:
            if kw in decoded_lower and kw not in found_keywords:
                found_keywords.add(kw)

        for pattern in urls_patterns:
            for match in re.findall(pattern, decoded):
                if match not in found_urls:
                    found_urls.add(match)

import os
import json

def export_report_json():
    global found_apis, found_keywords, found_iocs, Fname

    BASE_DIR = os.path.dirname(os.path.abspath(__file__))  # folder of main.py
    REPORT_FOLDER = os.path.join(BASE_DIR, "reports")
    os.makedirs(REPORT_FOLDER, exist_ok=True)

    i = 1
    while os.path.exists(os.path.join(REPORT_FOLDER, f"report{i}.json")):
        i += 1
    output_file = os.path.join(REPORT_FOLDER, f"report{i}.json")

    report = {
        "file": Fname,
        "apis": list(found_apis),
        "commands": list(found_keywords),
        "iocs": list(found_iocs)
    }

    with open(output_file, "w") as f:
        json.dump(report, f, indent=4)

    print(f"[+] Report exported to {output_file}")

def main():
    print("Some Fuckass Static Analysis Tool\n")
    print("File Information")
    print("~~~~~~~~~~")
    print(f"Name: {Fname} ")
    print(f"Size: {sz}")
    print(f"Type: {tp} ")
    print("\n")

    print("Hash's")
    print("~~~~~~~~~~")
    print(f"MD5: {calculate_hash(Fname, 'md5')} ")
    print(f"Sha256: {calculate_hash(Fname, 'sha256')}")
    print("\n")

    print("IoC")
    print("~~~~~~~~~~")
    for ioc in found_iocs:
        print(f"[IOC] {ioc}")
    print("\n")

    print("Suspicious Imports/API Calls")
    print("~~~~~~~~~~")
    for api in found_apis:
        print(f"[API] {api}")
    for kw in found_keywords:
        print(f"[CMD] {kw}")
    for ioc in found_urls:
        print(f"[IOC] {ioc}")
    print("\n")

    export_report_json()

info()
calculate_hash(Fname)
extract_strings()
susapi()
main()