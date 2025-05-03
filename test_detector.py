import os
import tkinter as tk
from tkinter import filedialog, ttk, messagebox  # Add ttk for progress bar and messagebox for alerts
import pefile  # Library for parsing PE files
from capstone import Cs, CS_ARCH_X86, CS_MODE_32  # Capstone for disassembly
import re
from tabulate import tabulate  # For creating formatted tables
from collections import defaultdict
import datetime
import pandas as pd  # For Excel export
import yara  # Add YARA library for rule-based detection
from tqdm import tqdm  # Add tqdm for the loading bar

THRESHOLD = 1551  # New threshold to classify a file as ransomware based on its score
# Define boolean flags and their weights
FLAGS = {
    "has_suspicious_sections": 150,   # Increased weight to 150
    "has_high_entropy": 200,           # Increased to 200
    "has_suspicious_imports": 100,     # Increased to 100
    "has_large_code_section": 125,     # Increased to 125
    "has_ransom_strings": 1000,        # Significantly increased to 1000
    "no_digital_signature": 250,       # Increased to 250
    "uses_encryption_apis": THRESHOLD,      # Increased to 1000 for strong detection
    "uses_other_apis": 100,            # Increased to 200
    "uses_crypto_dlls": 500,           # Increased to 500
    "uses_file_system_dlls": 100,      # Increased to 100
    "uses_internet_dlls": 200,         # Increased to 200
    "has_hardcoded_ips": 300,          # Increased to 300
    "has_hardcoded_urls": 250,         # Increased to 250
    "has_crypto_constants": 700,       # Increased to 700
    "has_hardcoded_commands": 600,     # Increased to 600
    "has_hardcoded_paths": 200,        # Increased to 200
    "uses_internet_access_functions": 800, # Increased to 300
    "uses_file_operations_functions": 200, # Increased to 250
    "uses_process_operations_functions": 400, # Increased to 500
    "uses_anti_debugging_functions": 300,   # Increased to 300
    "uses_service_operations_functions": 200, # Increased to 200
}

THRESHOLDS = {
    "ransom_words": 2,     # Threshold set to 300 occurrences for ransom-related words
    "other_apis": 5,       # Threshold set to 500 distinct other APIs
    "dll": 2,              # Set to 200 DLL occurrences
    "ip_url": 1,           # Threshold for IP and URL counts set to 150
    "crypto_constants": 1, # Threshold for crypto constants (RSA/AES) set to 400
    "commands": 1,         # Threshold for hardcoded commands (e.g., 'vssadmin') set to 350
    "paths": 2             # Threshold for hardcoded paths set to 250
}

def browse_folder():
    """Open a dialog to select a folder."""
    root = tk.Tk()
    root.withdraw()  # Hide the root window
    folder_path = filedialog.askdirectory(title="Select Folder")
    return folder_path

def find_executables(folder):
    """Recursively find all executable files in the folder and subfolders."""
    executables = []
    for root, _, files in os.walk(folder):
        for file in files:
            if file.endswith(('.exe', '.dll', '.sys')):  # Include other formats
                file_path = os.path.join(root, file)
                # Skip the detector script itself
                if os.path.abspath(file_path) == os.path.abspath(__file__):
                    continue
                executables.append(file_path)
    return executables

def load_yara_rules(rule_path):
    """Load YARA rules from a file."""
    try:
        rules = yara.compile(filepath=rule_path)
        return rules
    except Exception as e:
        print(f"Failed to load YARA rules: {e}")
        return None

def load_yara_rules_from_folder(folder_path):
    """Load all YARA rules from .yar files in the specified folder."""
    try:
        rule_files = [os.path.join(folder_path, f) for f in os.listdir(folder_path) if f.endswith('.yar')]
        if not rule_files:
            print("No .yar files found in the folder.")
            return None
        rules = yara.compile(filepaths={os.path.basename(f): f for f in rule_files})
        return rules
    except Exception as e:
        print(f"Failed to load YARA rules from folder: {e}")
        return None

def yara_scan(file_path, rules):
    """Scan a file with YARA rules and return matches."""
    try:
        matches = rules.match(file_path)
        return matches
    except Exception as e:
        print(f"Failed to scan {file_path} with YARA: {e}")
        return []

def analyze_executable(pe):
    """Analyze the executable and return a dictionary of boolean flags."""
    ransomware_words = ["ransom", "decrypt", "payment", "locked", "encrypt", "extortion", "wallet", "pay", "bitcoin", "keylogger", "malware"]
    encryption_apis = [
        "CryptEncrypt", "CryptDecrypt", "CryptGenKey", "CryptCreateHash", "CryptDeriveKey",
        "BCryptEncrypt", "BCryptDecrypt", "BCryptGenerateSymmetricKey", "BCryptHashData"
    ]
    other_apis = [
        "DeleteFile", "MoveFile", "CreateFile", "InternetOpen", "HttpSendRequest", 
        "RegSetValue", "RegCreateKey", "ShellExecute", "WinExec", "CreateProcess",
        "WriteFile", "ReadFile", "SetFileAttributes", "FindFirstFile", "FindNextFile",
        "GetFileAttributes", "SetFilePointer", "InternetReadFile", "InternetWriteFile"
    ]

    memory_image = pe.get_memory_mapped_image().decode(errors="ignore").lower()
    detected_words = [word for word in ransomware_words if word in memory_image]
    detected_count = sum(memory_image.count(word) for word in ransomware_words)  # Count occurrences of words
    distinct_detected_count = len(set(detected_words))  # Count distinct words

    # Patterns for detecting RSA public key blobs and AES S-box constants
    rsa_key_pattern = rb'\x30\x82[\x00-\xFF]{2}\x02\x82[\x00-\xFF]{2}\x00[\x00-\xFF]{128,}'  # ASN.1 DER-encoded RSA key
    aes_sbox_pattern = rb'\x63\x7c\x77\x7b\xf2\x6b\x6f\xc5\x30\x01\x67\x2b\xfe\xd7\xab\x76'  # AES S-box constants

    # Search for RSA keys and AES S-box constants in the memory-mapped image
    rsa_keys = re.findall(rsa_key_pattern, memory_image.encode(errors="ignore"))
    aes_sboxes = re.findall(aes_sbox_pattern, memory_image.encode(errors="ignore"))

    # Use distinct counts for RSA keys and AES S-box constants
    distinct_rsa_key_count = len(set(rsa_keys))
    distinct_aes_sbox_count = len(set(aes_sboxes))

    # Add more hardcoded commands commonly used by ransomware
    hardcoded_commands = [
        "vssadmin delete shadows", 
        "bcdedit /set {default} recoveryenabled no", 
        "cipher /w",
        "wbadmin delete catalog", 
        "vssadmin resize shadowstorage", 
        "schtasks /delete /tn", 
        "taskkill /f /im", 
        "icacls", 
        "takeown /f", 
        "attrib +h +s", 
        "del /f /q", 
        "net stop", 
        "netsh advfirewall set allprofiles state off",
        "powershell -command Remove-Item",  # PowerShell command to delete files
        "powershell -command Set-ExecutionPolicy",  # Modify execution policy
        "wmic shadowcopy delete",  # Deletes shadow copies
        "bcdedit /set safeboot minimal",  # Forces safe boot
        "bcdedit /deletevalue safeboot"  # Removes safe boot
    ]
    detected_commands = [cmd for cmd in hardcoded_commands if cmd in memory_image]
    distinct_command_count = len(set(detected_commands))

    # Updated regex pattern for detecting valid file paths
    path_pattern = r'([a-zA-Z]:\\(?:[a-zA-Z0-9._\-\\ ]+\\)*[a-zA-Z0-9._\- ]+)|(\.\.?\\(?:[a-zA-Z0-9._\-\\ ]+\\)*[a-zA-Z0-9._\- ]+)'

    # Search for hardcoded commands and paths in the memory-mapped image
    detected_paths = re.findall(path_pattern, memory_image)

    # Use distinct counts for commands and paths
    distinct_path_count = len(set(path[0] or path[1] for path in detected_paths if path[0] or path[1]))

    # Patterns for detecting hardcoded URLs
    url_pattern = r'https?://[^\s/$.?#].[^\s]*'
    hardcoded_urls = re.findall(url_pattern, memory_image)

    # Filter out Microsoft URLs
    microsoft_domains = ["microsoft.com", "windows.net", "msft.net"]
    filtered_urls = [
        url for url in hardcoded_urls
        if not any(domain in url for domain in microsoft_domains)
    ]
    distinct_url_count = len(set(filtered_urls))

    # Check for digital signature using the provided method
    try:
        sec_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']]
        has_digital_signature = sec_dir.VirtualAddress != 0 and sec_dir.Size != 0
    except Exception as e:
        has_digital_signature = False

    # Check for encryption-related APIs (case-insensitive matching)
    detected_encryption_apis = []
    detected_other_apis = []
    try:
        for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
            for imp in entry.imports:
                if imp.name:
                    api_name = imp.name.decode()
                    if api_name.lower() in [api.lower() for api in encryption_apis]:
                        detected_encryption_apis.append(api_name)
                    if api_name.lower() in [api.lower() for api in other_apis]:
                        detected_other_apis.append(api_name)
    except Exception as e:
        pass

    # Check for encryption-related APIs in memory (fallback)
    for api in encryption_apis:
        if api.lower() in memory_image:
            detected_encryption_apis.append(api)

    # Check for other APIs in memory (fallback)
    for api in other_apis:
        if api.lower() in memory_image:
            detected_other_apis.append(api)

    # Use distinct counts for other APIs
    distinct_other_apis_count = len(set(detected_other_apis))

    # Add more DLL categories for detection
    dll_categories = {
        "crypto_dlls": [
            "bcrypt.dll", "ncrypt.dll", "crypt32.dll", "advapi32.dll", "wincrypt.h",
            "libeay32.dll", "ssleay32.dll", "openssl.dll"
        ],
        "file_system_dlls": [
            "kernel32.dll", "shell32.dll", "shlwapi.dll", "ntdll.dll", "ole32.dll",
            "msvcrt.dll", "user32.dll", "gdi32.dll"
        ],
        "internet_dlls": [
            "wininet.dll", "winhttp.dll", "ws2_32.dll", "urlmon.dll", "httpapi.dll", "dnsapi.dll",
            "iphlpapi.dll", "netapi32.dll", "rasapi32.dll"
        ]
    }

    detected_dlls = {
        "crypto_dlls": [],
        "file_system_dlls": [],
        "internet_dlls": []
    }

    try:
        for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
            dll_name = entry.dll.decode().lower()
            for category, dll_list in dll_categories.items():
                if dll_name in dll_list:
                    detected_dlls[category].append(dll_name)
    except Exception as e:
        pass

    # Use distinct counts for DLLs
    distinct_crypto_dlls_count = len(set(detected_dlls["crypto_dlls"]))
    distinct_file_system_dlls_count = len(set(detected_dlls["file_system_dlls"]))
    distinct_internet_dlls_count = len(set(detected_dlls["internet_dlls"]))

    # Add more suspicious functions for categorization
    suspicious_function_categories = {
        "internet_access": {
            "functions": [
                "InternetOpen", "InternetConnect", "HttpOpenRequest", "HttpSendRequest",
                "WinHttpOpen", "WinHttpConnect", "WinHttpSendRequest", "socket", "connect", "send", "recv",
                "InternetReadFile", "InternetWriteFile", "DnsQuery", "getaddrinfo", "gethostbyname"
            ],
            "threshold": 2,
            "weight": FLAGS["uses_internet_access_functions"]
        },
        "file_operations": {
            "functions": [
                "CreateFile", "ReadFile", "WriteFile", "DeleteFile", "RemoveDirectory", "CopyFile",
                "SetFileAttributes", "FindFirstFile", "FindNextFile", "GetFileAttributes", "SetFilePointer"
            ],
            "threshold": 3,
            "weight": FLAGS["uses_file_operations_functions"]
        },
        "process_operations": {
            "functions": [
                "OpenProcess", "VirtualAlloc", "VirtualAllocEx", "WriteProcessMemory", "ReadProcessMemory",
                "CreateRemoteThread", "AdjustTokenPrivileges", "OpenProcessToken", "TerminateProcess",
                "CreateThread", "SuspendThread", "ResumeThread"
            ],
            "threshold": 2,
            "weight": FLAGS["uses_process_operations_functions"]
        },
        "anti_debugging": {
            "functions": [
                "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
                "GetTickCount", "QueryPerformanceCounter", "RDTSC", "NtDelayExecution",
                "OutputDebugString", "DebugBreak", "SetUnhandledExceptionFilter"
            ],
            "threshold": 2,
            "weight": FLAGS["uses_anti_debugging_functions"]
        },
        "service_operations": {
            "functions": [
                "CreateService", "OpenService", "StartService", "ControlService", "DeleteService",
                "QueryServiceStatus", "ChangeServiceConfig"
            ],
            "threshold": 1,
            "weight": FLAGS["uses_service_operations_functions"]
        }
    }

    detected_suspicious_functions = {category: [] for category in suspicious_function_categories}

    try:
        for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
            for imp in entry.imports:
                if imp.name:
                    api_name = imp.name.decode()
                    # Check each category
                    for category, details in suspicious_function_categories.items():
                        if api_name.lower() in [func.lower() for func in details["functions"]]:
                            detected_suspicious_functions[category].append(api_name)
    except Exception as e:
        pass

    # Check for suspicious functions in memory (fallback)
    for category, details in suspicious_function_categories.items():
        for func in details["functions"]:
            if func.lower() in memory_image:
                detected_suspicious_functions[category].append(func)

    # Calculate distinct counts for each category
    distinct_suspicious_function_counts = {
        category: len(set(functions))
        for category, functions in detected_suspicious_functions.items()
    }

    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'

    # Search for IP addresses in the memory-mapped image
    hardcoded_ips = re.findall(ip_pattern, memory_image)

    # Use distinct counts for IPs
    distinct_ip_count = len(set(hardcoded_ips))

    flags = {
        "has_suspicious_sections": any(
            section.Name.decode().strip() in [".text", ".data", ".rsrc"] and section.SizeOfRawData == 0
            for section in pe.sections
        ),
        "has_high_entropy": any(
            section.get_entropy() > 7.9 for section in pe.sections
        ),
        "has_suspicious_imports": any(
            imp.name and imp.name.decode() in ["CreateFileA", "WriteFile", "DeleteFileA"]
            for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", [])
            for imp in entry.imports
        ),
        "has_large_code_section": any(
            section.Name.decode().strip() == ".text" and section.Misc_VirtualSize > 1000000
            for section in pe.sections
        ),
        "has_ransom_strings": distinct_detected_count >= THRESHOLDS["ransom_words"],  # Trigger flag if count exceeds threshold
        "no_digital_signature": not has_digital_signature,  # Trigger flag if no digital signature
        "uses_encryption_apis": bool(detected_encryption_apis),  # Trigger flag if encryption APIs are detected
        "uses_other_apis": distinct_other_apis_count >= THRESHOLDS["other_apis"],  # Trigger flag if distinct count exceeds threshold
        "uses_crypto_dlls": distinct_crypto_dlls_count >= THRESHOLDS["dll"],
        "uses_file_system_dlls": distinct_file_system_dlls_count >= THRESHOLDS["dll"],
        "uses_internet_dlls": distinct_internet_dlls_count >= THRESHOLDS["dll"],
        "has_hardcoded_ips": distinct_ip_count >= THRESHOLDS["ip_url"],
        "has_hardcoded_urls": distinct_url_count >= THRESHOLDS["ip_url"],
        "has_crypto_constants": distinct_rsa_key_count + distinct_aes_sbox_count >= THRESHOLDS["crypto_constants"],
        "has_hardcoded_commands": distinct_command_count >= THRESHOLDS["commands"],
        "has_hardcoded_paths": distinct_path_count >= THRESHOLDS["paths"],
    }
    for category, details in suspicious_function_categories.items():
        flags[f"uses_{category}_functions"] = distinct_suspicious_function_counts[category] >= details["threshold"]

    # Collect counts for the counts table
    counts = {
        "ransom_words": distinct_detected_count,
        "encryption_apis": len(set(detected_encryption_apis)),
        "other_apis": distinct_other_apis_count,
        "crypto_dlls": distinct_crypto_dlls_count,
        "file_system_dlls": distinct_file_system_dlls_count,
        "internet_dlls": distinct_internet_dlls_count,
        "hardcoded_ips": distinct_ip_count,
        "hardcoded_urls": distinct_url_count,
        "rsa_keys": distinct_rsa_key_count,
        "aes_constants": distinct_aes_sbox_count,
        "hardcoded_commands": distinct_command_count,
        "hardcoded_paths": distinct_path_count,
    }
    
    # Add suspicious function counts
    for category, count in distinct_suspicious_function_counts.items():
        counts[f"{category}_functions"] = count

    return flags, counts

def calculate_score(flags):
    """Calculate the score based on the flags and their weights."""
    score = sum(weight for flag, weight in FLAGS.items() if flags.get(flag, False))
    return score

def decompile_executable(file_path, yara_rules=None):
    """Decompile an executable, analyze it, and calculate its score."""
    try:
        pe = pefile.PE(file_path)
        
        # Analyze the executable
        flags, counts = analyze_executable(pe)
        
        # Calculate the score
        score = calculate_score(flags)
        
        # Perform YARA scan if rules are provided
        yara_matches = yara_scan(file_path, yara_rules) if yara_rules else []
        
        # Return the results
        is_ransomware = score >= THRESHOLD
        return {
            "file_path": file_path,
            "flags": flags,
            "counts": counts,
            "score": score,
            "is_ransomware": is_ransomware,
            "yara_matches": [match.rule for match in yara_matches]  # Extract rule names
        }
    except Exception as e:
        print(f"Failed to decompile {file_path}: {e}")
        return None

def display_results(results):
    """Display results in table format and save to an Excel file."""
    if not results:
        print("No results to display.")
        return
    
    # Create timestamp for output files
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    # Create a logs subdirectory in the same folder as the script
    script_dir = os.path.dirname(os.path.abspath(__file__))
    log_dir = os.path.join(script_dir, "logs")
    os.makedirs(log_dir, exist_ok=True)  # Ensure the logs folder exists
    
    # Prepare data for flag table
    excel_flags_data = []
    for result in results:
        if result is None:
            continue
        
        excel_row = {
            "File": os.path.basename(result["file_path"]),
            "Score": result["score"],
            "Is Ransomware": result["is_ransomware"]
        }
        # Add all flags with boolean values
        for flag, value in result["flags"].items():
            excel_row[flag] = value
        excel_flags_data.append(excel_row)
    
    # Prepare data for counts table
    excel_counts_data = []
    if results[0] and "counts" in results[0]:
        for result in results:
            if result is None:
                continue
                
            excel_row = {"File": os.path.basename(result["file_path"])}
            for count_key, count_value in result["counts"].items():
                excel_row[count_key] = count_value
            excel_counts_data.append(excel_row)
    
    # Prepare data for YARA matches
    yara_data = []
    for result in results:
        if result is None:
            continue
        yara_row = {
            "File": os.path.basename(result["file_path"]),
            "YARA Matches": ", ".join(result["yara_matches"]) if result["yara_matches"] else "None"
        }
        yara_data.append(yara_row)
    
    # Create Excel file with three sheets
    excel_path = os.path.join(log_dir, f"ransomware_analysis_{timestamp}.xlsx")
    
    try:
        # Convert data to pandas DataFrames
        flags_df = pd.DataFrame(excel_flags_data)
        counts_df = pd.DataFrame(excel_counts_data)
        yara_df = pd.DataFrame(yara_data)
        
        # Create Excel writer
        with pd.ExcelWriter(excel_path) as writer:
            # Write each dataframe to a different sheet
            flags_df.to_excel(writer, sheet_name='Analysis Flags', index=False)
            counts_df.to_excel(writer, sheet_name='Detection Counts', index=False)
            yara_df.to_excel(writer, sheet_name='YARA Matches', index=False)
        
        print(f"\nLogs saved to Excel file:\n- {excel_path}")
    except Exception as e:
        print(f"\nFailed to create Excel file: {e}")

def display_summary(results):
    """Display a summary of the analysis in a user-friendly format."""
    print("\nSummary of Analysis:")
    summary_data = []
    for result in results:
        if result is None:
            continue
        summary_data.append([
            os.path.basename(result["file_path"]),
            result["score"],
            "Yes" if result["is_ransomware"] else "No",
            ", ".join(result["yara_matches"]) if result["yara_matches"] else "None"
        ])
    headers = ["File", "Score", "Ransomware Detected", "YARA Matches"]
    print(tabulate(summary_data, headers=headers, tablefmt="grid"))

def show_summary_ui(results):
    """Display the summary in a tkinter UI."""
    root = tk.Tk()
    root.title("Ransomware Detection Summary")
    
    # Calculate total ransomware files
    total_files = len(results)
    ransomware_files = sum(1 for result in results if result and result["is_ransomware"])
    
    # Add a label to display the total ransomware count
    summary_label = tk.Label(
        root, 
        text=f"Total Files: {total_files} | Ransomware Detected: {ransomware_files}",
        font=("Arial", 12, "bold")
    )
    summary_label.pack(pady=10)
    
    # Create a treeview to display the results
    tree = ttk.Treeview(root, columns=("File", "Score", "Ransomware Detected", "YARA Matches"), show="headings")
    tree.heading("File", text="File")
    tree.heading("Score", text="Score")
    tree.heading("Ransomware Detected", text="Ransomware Detected")
    tree.heading("YARA Matches", text="YARA Matches")
    tree.column("File", width=200)
    tree.column("Score", width=80)
    tree.column("Ransomware Detected", width=150)
    tree.column("YARA Matches", width=200)
    
    # Insert results into the treeview
    for result in results:
        if result is None:
            continue
        tree.insert("", "end", values=(
            os.path.basename(result["file_path"]),
            result["score"],
            "Yes" if result["is_ransomware"] else "No",
            ", ".join(result["yara_matches"]) if result["yara_matches"] else "None"
        ))
    
    tree.pack(fill="both", expand=True)
    
    # Add a close button
    close_button = ttk.Button(root, text="Close", command=root.destroy)
    close_button.pack(pady=10)
    
    root.mainloop()

def process_folder():
    """Main function to browse folder, find executables, and decompile them."""
    folder = browse_folder()
    if not folder:
        messagebox.showinfo("No Folder Selected", "Please select a folder to analyze.")
        return

    # Load YARA rules from the same folder as the script
    script_dir = os.path.dirname(os.path.abspath(__file__))
    yara_rules = load_yara_rules_from_folder(script_dir)
    if yara_rules is None:
        messagebox.showwarning("YARA Rules Missing", "YARA rules not loaded. Skipping YARA detection.")
    
    executables = find_executables(folder)
    if not executables:
        messagebox.showinfo("No Executables Found", "No executables found in the selected folder.")
        return
    
    # Create a progress window
    progress_window = tk.Tk()
    progress_window.title("Analyzing Files")
    tk.Label(progress_window, text="Analyzing files, please wait...").pack(pady=10)
    progress_bar = ttk.Progressbar(progress_window, length=300, mode="determinate", maximum=len(executables))
    progress_bar.pack(pady=10)
    progress_window.update()
    
    # Collect results for all executables
    results = []
    for i, exe in enumerate(executables):
        progress_bar["value"] = i + 1
        progress_window.update()
        result = decompile_executable(exe, yara_rules)
        results.append(result)
    
    progress_window.destroy()  # Close the progress window
    
    # Display results in table format
    display_results(results)
    
    # Show the summary in a UI
    show_summary_ui(results)

if __name__ == "__main__":
    process_folder()








