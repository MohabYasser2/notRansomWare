import os
import tkinter as tk
from tkinter import filedialog
import pefile  # Library for parsing PE files
from capstone import Cs, CS_ARCH_X86, CS_MODE_32  # Capstone for disassembly
import re
from tabulate import tabulate  # For creating formatted tables
from collections import defaultdict
import datetime
import pandas as pd  # For Excel export

# Define boolean flags and their weights
FLAGS = {
    "has_suspicious_sections": 5,
    "has_high_entropy": 4,
    "has_suspicious_imports": 6,
    "has_large_code_section": 3,
    "has_ransom_strings": 7,  # New flag for ransom-related strings
    "no_digital_signature": 2,  # New flag for missing digital signature
    "uses_encryption_apis": 5,  # New flag for encryption-related APIs
    "uses_other_apis": 1,  # New flag for other APIs
    "uses_suspicious_functions": 6,  # New flag for suspicious functions
    "uses_crypto_dlls": 3,  # New flag for crypto DLLs
    "uses_file_system_dlls": 2,  # New flag for file system DLLs
    "uses_internet_dlls": 4,  # New flag for internet DLLs
    "has_hardcoded_ips": 3,  # New flag for hardcoded IPs
    "has_hardcoded_urls": 3,  # New flag for hardcoded URLs
    "has_crypto_constants": 5,  # New flag for detecting RSA/AES constants
    "has_hardcoded_commands": 4,  # New flag for hardcoded commands
    "has_hardcoded_paths": 3,  # New flag for hardcoded paths
}

THRESHOLD = 10  # Threshold score to classify as ransomware

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

def analyze_executable(pe):
    """Analyze the executable and return a dictionary of boolean flags."""
    ransomware_words = ["ransom", "decrypt", "payment", "locked", "encrypt", "extortion", "wallet" ,"pay"]
    encryption_apis = ["CryptEncrypt", "CryptDecrypt", "CryptGenKey", "CryptCreateHash", "CryptDeriveKey"]
    other_apis = ["DeleteFile", "MoveFile", "CreateFile", "InternetOpen", "HttpSendRequest", 
                  "RegSetValue", "RegCreateKey", "ShellExecute", "WinExec", "CreateProcess"]
   
    memory_image = pe.get_memory_mapped_image().decode(errors="ignore").lower()
    detected_words = [word for word in ransomware_words if word in memory_image]
    detected_count = sum(memory_image.count(word) for word in ransomware_words)  # Count occurrences of words
    distinct_detected_count = len(set(detected_words))  # Count distinct words

    RANSOM_WORDS_THRESHOLD = 4  # Threshold for triggering the ransom strings flag
    OTHER_APIS_THRESHOLD = 3  # Threshold for triggering the other APIs flag
    DLL_THRESHOLD = 2  # Threshold for triggering DLL-related flags
    IP_URL_THRESHOLD = 1  # Threshold for triggering the hardcoded IP/URL flag

    # Patterns for detecting RSA public key blobs and AES S-box constants
    rsa_key_pattern = rb'\x30\x82[\x00-\xFF]{2}\x02\x82[\x00-\xFF]{2}\x00[\x00-\xFF]{128,}'  # ASN.1 DER-encoded RSA key
    aes_sbox_pattern = rb'\x63\x7c\x77\x7b\xf2\x6b\x6f\xc5\x30\x01\x67\x2b\xfe\xd7\xab\x76'  # AES S-box constants

    # Search for RSA keys and AES S-box constants in the memory-mapped image
    rsa_keys = re.findall(rsa_key_pattern, memory_image.encode(errors="ignore"))
    aes_sboxes = re.findall(aes_sbox_pattern, memory_image.encode(errors="ignore"))

    # Use distinct counts for RSA keys and AES S-box constants
    distinct_rsa_key_count = len(set(rsa_keys))
    distinct_aes_sbox_count = len(set(aes_sboxes))

    # Threshold for RSA/AES detection
    CRYPTO_CONSTANTS_THRESHOLD = 1

    # Patterns for detecting hardcoded commands and paths
    hardcoded_commands = [
        "vssadmin delete shadows", 
        "bcdedit /set {default} recoveryenabled no", 
        "cipher /w",
        "wbadmin delete catalog",  # Deletes backup catalog
        "vssadmin resize shadowstorage",  # Modifies shadow storage
        "schtasks /delete /tn",  # Deletes scheduled tasks
        "taskkill /f /im",  # Forcefully kills processes
        "icacls",  # Modifies file permissions
        "takeown /f",  # Takes ownership of files
        "attrib +h +s",  # Hides files
        "del /f /q",  # Deletes files forcefully and quietly
        "net stop",  # Stops services
        "netsh advfirewall set allprofiles state off"  # Disables firewall
    ]
    # Updated regex pattern for detecting valid file paths
    path_pattern = r'([a-zA-Z]:\\(?:[a-zA-Z0-9._\-\\ ]+\\)*[a-zA-Z0-9._\- ]+)|(\.\.?\\(?:[a-zA-Z0-9._\-\\ ]+\\)*[a-zA-Z0-9._\- ]+)'

    # Search for hardcoded commands and paths in the memory-mapped image
    detected_commands = [cmd for cmd in hardcoded_commands if cmd in memory_image]
    detected_paths = re.findall(path_pattern, memory_image)

    # Use distinct counts for commands and paths
    distinct_command_count = len(set(detected_commands))
    distinct_path_count = len(set(path[0] or path[1] for path in detected_paths if path[0] or path[1]))

    # Threshold for hardcoded commands and paths
    COMMANDS_THRESHOLD = 1
    PATHS_THRESHOLD = 1

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

    dll_categories = {
        "crypto_dlls": ["bcrypt.dll", "ncrypt.dll", "crypt32.dll", "advapi32.dll", "wincrypt.h"],
        "file_system_dlls": ["kernel32.dll", "shell32.dll", "shlwapi.dll", "ntdll.dll", "ole32.dll"],
        "internet_dlls": ["wininet.dll", "winhttp.dll", "ws2_32.dll", "urlmon.dll", "httpapi.dll", "dnsapi.dll"]
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

    # Categorize suspicious functions
    suspicious_function_categories = {
        "internet_access": {
            "functions": ["InternetOpen", "InternetConnect", "HttpOpenRequest", "HttpSendRequest",
                          "WinHttpOpen", "WinHttpConnect", "WinHttpSendRequest", "socket", "connect", "send", "recv"],
            "threshold": 3,
            "weight": 4
        },
        "file_operations": {
            "functions": ["CreateFile", "ReadFile", "WriteFile", "DeleteFile", "RemoveDirectory", "CopyFile"],
            "threshold": 3,
            "weight": 3
        },
        "process_operations": {
            "functions": ["OpenProcess", "VirtualAlloc", "VirtualAllocEx", "WriteProcessMemory", "ReadProcessMemory",
                          "CreateRemoteThread", "AdjustTokenPrivileges", "OpenProcessToken"],
            "threshold": 2,
            "weight": 5
        },
        "anti_debugging": {
            "functions": ["IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
                          "GetTickCount", "QueryPerformanceCounter", "RDTSC", "NtDelayExecution"],
            "threshold": 2,
            "weight": 3
        },
        "service_operations": {
            "functions": ["CreateService", "OpenService", "StartService"],
            "threshold": 1,
            "weight": 2
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
    url_pattern = r'https?://[^\s/$.?#].[^\s]*'

    # Search for IP addresses and URLs in the memory-mapped image
    hardcoded_ips = re.findall(ip_pattern, memory_image)
    hardcoded_urls = re.findall(url_pattern, memory_image)

    # Filter out Microsoft URLs
    microsoft_domains = ["microsoft.com", "windows.net", "msft.net"]
    filtered_urls = [
        url for url in hardcoded_urls
        if not any(domain in url for domain in microsoft_domains)
    ]

    # Use distinct counts for IPs and filtered URLs
    distinct_ip_count = len(set(hardcoded_ips))
    distinct_url_count = len(set(filtered_urls))

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
        "has_ransom_strings": distinct_detected_count >= RANSOM_WORDS_THRESHOLD,  # Trigger flag if count exceeds threshold
        "no_digital_signature": not has_digital_signature,  # Trigger flag if no digital signature
        "uses_encryption_apis": bool(detected_encryption_apis),  # Trigger flag if encryption APIs are detected
        "uses_other_apis": distinct_other_apis_count >= OTHER_APIS_THRESHOLD,  # Trigger flag if distinct count exceeds threshold
        "uses_crypto_dlls": distinct_crypto_dlls_count >= DLL_THRESHOLD,
        "uses_file_system_dlls": distinct_file_system_dlls_count >= DLL_THRESHOLD,
        "uses_internet_dlls": distinct_internet_dlls_count >= DLL_THRESHOLD,
        "has_hardcoded_ips": distinct_ip_count >= IP_URL_THRESHOLD,
        "has_hardcoded_urls": distinct_url_count >= IP_URL_THRESHOLD,
        "has_crypto_constants": distinct_rsa_key_count + distinct_aes_sbox_count >= CRYPTO_CONSTANTS_THRESHOLD,
        "has_hardcoded_commands": distinct_command_count >= COMMANDS_THRESHOLD,
        "has_hardcoded_paths": distinct_path_count >= PATHS_THRESHOLD,
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

def decompile_executable(file_path):
    """Decompile an executable, analyze it, and calculate its score."""
    try:
        pe = pefile.PE(file_path)
        
        # Analyze the executable
        flags, counts = analyze_executable(pe)
        
        # Calculate the score
        score = calculate_score(flags)
        
        # Return the results
        is_ransomware = score >= THRESHOLD
        return {
            "file_path": file_path,
            "flags": flags,
            "counts": counts,
            "score": score,
            "is_ransomware": is_ransomware
        }
    except Exception as e:
        print(f"Failed to decompile {file_path}: {e}")
        return None

def display_results(results):
    """Display results in table format and save to log files and Excel."""
    if not results:
        print("No results to display.")
        return
    
    # Create timestamp for output files
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    log_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs")
    os.makedirs(log_dir, exist_ok=True)
    
    # Use ASCII characters for file output to avoid encoding issues
    true_mark = "YES"
    false_mark = "NO"
    
    # Prepare data for flag table (for display)
    flag_headers = ["File"]
    flag_headers.extend(FLAGS.keys())
    flag_headers.append("Score")
    flag_headers.append("Is Ransomware")
    
    # For console display (can use Unicode)
    flag_rows_display = []
    # For file output (ASCII only)
    flag_rows_file = []
    # For Excel export (boolean values)
    excel_flags_data = []
    
    for result in results:
        if result is None:
            continue
        
        # For display with Unicode symbols
        row_display = [os.path.basename(result["file_path"])]
        for flag in FLAGS.keys():
            row_display.append("✓" if result["flags"].get(flag, False) else "✗")
        row_display.append(result["score"])
        row_display.append("YES" if result["is_ransomware"] else "NO")
        flag_rows_display.append(row_display)
        
        # For file output with ASCII-only
        row_file = [os.path.basename(result["file_path"])]
        for flag in FLAGS.keys():
            row_file.append(true_mark if result["flags"].get(flag, False) else false_mark)
        row_file.append(result["score"])
        row_file.append("YES" if result["is_ransomware"] else "NO")
        flag_rows_file.append(row_file)
        
        # For Excel with actual boolean values and numbers
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
        count_headers = ["File"]
        count_headers.extend(results[0]["counts"].keys())
        
        count_rows = []
        for result in results:
            if result is None:
                continue
                
            row = [os.path.basename(result["file_path"])]
            for count_key in results[0]["counts"].keys():
                row.append(result["counts"].get(count_key, 0))
            count_rows.append(row)
            
            # For Excel with structured data
            excel_row = {"File": os.path.basename(result["file_path"])}
            for count_key, count_value in result["counts"].items():
                excel_row[count_key] = count_value
            excel_counts_data.append(excel_row)
    
    # Generate tables
    flags_table_display = tabulate(flag_rows_display, flag_headers, tablefmt="grid")
    flags_table_file = tabulate(flag_rows_file, flag_headers, tablefmt="grid")
    counts_table = tabulate(count_rows, count_headers, tablefmt="grid")
    
    # Display tables in console (can use Unicode)
    print("\n--- ANALYSIS FLAGS ---")
    print(flags_table_display)
    
    print("\n--- DETECTED COUNTS ---")
    print(counts_table)
    
    # Summary
    ransomware_count = sum(1 for result in results if result and result["is_ransomware"])
    summary_text = f"\nSummary: {ransomware_count} out of {len([r for r in results if r is not None])} files classified as ransomware."
    print(summary_text)
    
    # Save to log files with explicit UTF-8 encoding
    flags_log_path = os.path.join(log_dir, f"analysis_flags_{timestamp}.txt")
    counts_log_path = os.path.join(log_dir, f"detection_counts_{timestamp}.txt")
    
    try:
        # Use UTF-8 encoding for file writing
        with open(flags_log_path, "w", encoding="utf-8") as f:
            f.write("ANALYSIS FLAGS\n")
            f.write(flags_table_display)
            f.write(f"\n{summary_text}")
    except UnicodeEncodeError:
        # Fallback to ASCII version if UTF-8 fails
        with open(flags_log_path, "w") as f:
            f.write("ANALYSIS FLAGS\n")
            f.write(flags_table_file)
            f.write(f"\n{summary_text}")
    
    with open(counts_log_path, "w") as f:
        f.write("DETECTED COUNTS\n")
        f.write(counts_table)
    
    # Create Excel file with two sheets
    excel_path = os.path.join(log_dir, f"ransomware_analysis_{timestamp}.xlsx")
    
    try:
        # Convert data to pandas DataFrames
        flags_df = pd.DataFrame(excel_flags_data)
        counts_df = pd.DataFrame(excel_counts_data)
        
        # Create Excel writer
        with pd.ExcelWriter(excel_path) as writer:
            # Write each dataframe to a different sheet
            flags_df.to_excel(writer, sheet_name='Analysis Flags', index=False)
            counts_df.to_excel(writer, sheet_name='Detection Counts', index=False)
            
            # Auto-adjust columns' width
            for sheet in writer.sheets:
                worksheet = writer.sheets[sheet]
                for i, col in enumerate(flags_df.columns if sheet == 'Analysis Flags' else counts_df.columns):
                    # Find the maximum length of the column
                    max_len = max(
                        flags_df[col].astype(str).map(len).max() if sheet == 'Analysis Flags' else counts_df[col].astype(str).map(len).max(),
                        len(str(col))
                    ) + 2  # Add a little extra space
                    # Set the column width
                    worksheet.column_dimensions[chr(65 + i)].width = max_len
        
        print(f"\nLogs saved to:\n- {flags_log_path}\n- {counts_log_path}\n- {excel_path}")
    except Exception as e:
        print(f"\nFailed to create Excel file: {e}")
        print(f"\nText logs saved to:\n- {flags_log_path}\n- {counts_log_path}")

def process_folder():
    """Main function to browse folder, find executables, and decompile them."""
    folder = browse_folder()
    if not folder:
        print("No folder selected.")
        return

    executables = find_executables(folder)
    if not executables:
        print("No executables found in the selected folder.")
        return
    
    print(f"Found {len(executables)} executable(s). Analyzing...")
    
    # Collect results for all executables
    results = []
    for exe in executables:
        print(f"Analyzing: {os.path.basename(exe)}...")
        result = decompile_executable(exe)
        results.append(result)
    
    # Display results in table format
    display_results(results)

if __name__ == "__main__":
    process_folder()


