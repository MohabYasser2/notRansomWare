import os
import pefile
import numpy as np
from scipy.stats import entropy
import re
import tkinter as tk
from tkinter import filedialog, messagebox

def calculate_entropy(data):
    if len(data) == 0:
        return 0
    value, counts = np.unique(np.frombuffer(data, dtype=np.uint8), return_counts=True)
    return entropy(counts, base=2)

def has_valid_signature(pe):
    try:
        security_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']]
        # If size > 0 and address maps to a file offset, consider it signed
        return security_dir.Size > 0 and security_dir.VirtualAddress != 0
    except:
        return False

def detect_xor_behavior(pe):
    # Check for XOR-related strings or imports in the executable
    xor_keywords = ["xor", "key", "encrypt", "decrypt"]
    file_api_keywords = ["CreateFile", "ReadFile", "WriteFile", "DeleteFile"]

    # Check imports for file manipulation APIs
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                if imp.name:
                    imp_name = imp.name.decode(errors="ignore").lower()
                    if any(api.lower() in imp_name for api in file_api_keywords):
                        return True

    # Check strings for XOR-related keywords
    try:
        strings = pe.get_memory_mapped_image().decode(errors="ignore").lower()
        if any(keyword in strings for keyword in xor_keywords):
            return True
    except Exception:
        pass

    return False

def extract_enhanced_indicators(file_path):
    # Base indicators (binary)
    binary_indicators = {
        "high_entropy_section": 0,
        "high_entropy_text": 0,
        "encryption_apis": 0,
        "suspicious_apis": 0,
        "ransom_strings": 0,
        "bitcoin_address": 0,
        "unusual_sections": 0,
        "embedded_scripts": 0,
        "no_digital_signature": 0,
        "packer_upx": 0,
        "high_entropy_entrypoint": 0,
        "target_extensions": 0,
        "suspicious_exports": 0,
        "side_loading_dll": 0,
        "suspicious_extension": 0,  # New indicator for suspicious extensions
        "xor_behavior": 0,  # New indicator for XOR behavior
    }

    # Continuous indicators and additional features
    continuous_indicators = {
        "max_entropy": 0.0,
        "text_entropy": 0.0,
        "entry_entropy": 0.0,
        "avg_entropy": 0.0,
        "section_count": 0,
        "file_size_kb": 0.0,
        "import_count": 0,
        "export_count": 0,
        "string_entropy": 0.0,
    }

    try:
        # Load the PE file
        pe = pefile.PE(file_path, fast_load=True)
        pe.parse_data_directories()
        print("== Signature Debug for:", file_path)
        try:
            sec_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']]
            print("  VirtualAddress:", hex(sec_dir.VirtualAddress))
            print("  Size:", hex(sec_dir.Size))
        except Exception as e:
            print("  Failed to access signature directory:", e)

        # Get file size
        continuous_indicators["file_size_kb"] = os.path.getsize(file_path) / 1024.0

        # Process sections
        section_entropies = []
        for section in pe.sections:
            section_data = section.get_data()
            section_entropy = calculate_entropy(section_data)
            section_entropies.append(section_entropy)

            if section_entropy > 7.5:
                binary_indicators["high_entropy_section"] = 1

            section_name = section.Name.decode(errors="ignore").rstrip("\x00")
            if section_name == ".text":
                continuous_indicators["text_entropy"] = section_entropy
                if section_entropy > 7.0:
                    binary_indicators["high_entropy_text"] = 1

            # Check for unusual section names
            unusual_sections = [".crypto", ".ransom"]
            if any(unusual in section_name for unusual in unusual_sections):
                binary_indicators["unusual_sections"] = 1

        # Calculate section statistics
        if section_entropies:
            continuous_indicators["max_entropy"] = max(section_entropies)
            continuous_indicators["avg_entropy"] = sum(section_entropies) / len(section_entropies)
            continuous_indicators["section_count"] = len(section_entropies)

        # Process entry point
        entry_point_data = pe.get_data(pe.OPTIONAL_HEADER.AddressOfEntryPoint, 1024)
        entry_entropy = calculate_entropy(entry_point_data)
        continuous_indicators["entry_entropy"] = entry_entropy
        if entry_entropy > 7.5:
            binary_indicators["high_entropy_entrypoint"] = 1

        # Process imports
        import_count = 0
        suspicious_count=0
        encryption_apis = ["CryptEncrypt", "CryptDecrypt", "CryptGenKey", "CryptCreateHash", "CryptDeriveKey"]
        other_apis = ["DeleteFile", "MoveFile", "CreateFile", "InternetOpen", "HttpSendRequest", 
                    "RegSetValue", "RegCreateKey", "ShellExecute", "WinExec", "CreateProcess"]

        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    import_count += 1
                    if imp.name:
                        imp_name = imp.name.decode(errors="ignore").lower()
                        if any(api.lower() in imp_name for api in encryption_apis):
                            binary_indicators["encryption_apis"] = 1
                        if any(api.lower() in imp_name for api in other_apis):
                            suspicious_count += 1

            if suspicious_count >= 3:  # Only flag if 3 or more suspicious APIs
                binary_indicators["suspicious_apis"] = 1
            print("Suspicious API count:", suspicious_count)
            print("Flagged suspicious_apis:", binary_indicators["suspicious_apis"])

        continuous_indicators["import_count"] = import_count

        # Process exports
        export_count = 0
        if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
            export_count = len(pe.DIRECTORY_ENTRY_EXPORT.symbols)
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if exp.name and any(keyword in exp.name.decode(errors="ignore").lower() 
                                 for keyword in ["encrypt", "delete", "ransom", "lock"]):
                    binary_indicators["suspicious_exports"] = 1
        continuous_indicators["export_count"] = export_count

        # Digital signature
        if not has_valid_signature(pe):
            binary_indicators["no_digital_signature"] = 1



        # Read file content for string-based indicators
        with open(file_path, "rb") as f:
            content = f.read()
            text_content = content.decode(errors="ignore").lower()

            # Calculate string entropy
            continuous_indicators["string_entropy"] = calculate_entropy(content)

        1

        # Check for XOR behavior
        if detect_xor_behavior(pe):
            binary_indicators["xor_behavior"] = 1

        # Check for suspicious extensions
        suspicious_extensions = [".encrypted", ".lock", ".crypt"]
        if any(file_path.endswith(ext) for ext in suspicious_extensions):
            binary_indicators["suspicious_extension"] = 1

        # Ransom-related strings
        ransom_keywords = [
            "ransom", "bitcoin", "encrypted", "decrypt", "pay", "wallet",
            ".locked", ".crypt", "tor", "onion", "payment", "deadline", "btc", "monero"
        ]
        if any(keyword in text_content for keyword in ransom_keywords):
            binary_indicators["ransom_strings"] = 1

        # Bitcoin addresses
        bitcoin_pattern = r'\\b(1|3|bc1)[A-Za-z0-9]{25,34}\\b'
        if re.search(bitcoin_pattern, text_content):
            binary_indicators["bitcoin_address"] = 1

        # Embedded scripts
        script_keywords = ["powershell.exe", "cmd.exe", "schtasks", "wscript.exe", "cscript.exe"]
        if any(keyword in text_content for keyword in script_keywords):
            binary_indicators["embedded_scripts"] = 1

        # Packer detection
        if "UPX" in text_content or "UPX0" in text_content or "UPX1" in text_content:
            binary_indicators["packer_upx"] = 1

        # Targeted file extensions
        target_extensions = [".doc", ".pdf", ".jpg", ".docx", ".xlsx", ".txt", ".zip", ".rar"]
        if any(ext in text_content for ext in target_extensions):
            binary_indicators["target_extensions"] = 1

        # DLL side-loading filenames
        side_load_dlls = ["version.dll", "wininet.dll", "msvcr100.dll", "msvcp100.dll"]
        if any(dll in os.path.basename(file_path).lower() for dll in side_load_dlls):
            binary_indicators["side_loading_dll"] = 1

        pe.close()

    except Exception as e:
        print(f"Error processing {file_path}: {str(e)}")
        # All indicators default to 0 if there's an error

    # Create combined feature set
    indicators = {}
    indicators.update(binary_indicators)
    indicators.update(continuous_indicators)

    # Add compound features (feature interactions)
    indicators["crypto_api_with_high_entropy"] = 1 if (binary_indicators["encryption_apis"] == 1 and 
                                                   binary_indicators["high_entropy_section"] == 1) else 0
    indicators["suspicious_api_with_scripts"] = 1 if (binary_indicators["suspicious_apis"] == 1 and 
                                                  binary_indicators["embedded_scripts"] == 1) else 0
    indicators["bitcoin_with_ransom_strings"] = 1 if (binary_indicators["bitcoin_address"] == 1 and 
                                                 binary_indicators["ransom_strings"] == 1) else 0
    indicators["high_entropy_unsigned"] = 1 if (binary_indicators["high_entropy_section"] == 1 and 
                                           binary_indicators["no_digital_signature"] == 1) else 0

    # Assign weights to indicators
    indicator_weights = {
    # Critical Indicators (Strong ransomware correlation)
    "encryption_apis": 25,          # CryptEncrypt, CryptGenKey, etc. (Core to ransomware)
    "ransom_strings": 20,           # "Your files are encrypted", "Pay Bitcoin", etc.
    "bitcoin_address": 20,          # Direct financial motive (e.g., "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")
    "crypto_api_with_high_entropy": 25, # Encryption APIs + high entropy = strong ransomware signal
    
    # High-Value Behavioral Indicators
    "suspicious_apis": 15,          # DeleteFile, CreateRemoteThread, etc.
    "high_entropy_section": 12,     # Packed/encrypted code (common in ransomware)
    "high_entropy_entrypoint": 12,  # Obfuscated entry point (e.g., UPX packers)
    "suspicious_exports": 10,       # Exports like "encrypt_files"
    "bitcoin_with_ransom_strings": 20, # Bitcoin + ransom note = near-certain ransomware
    
    # Moderate Indicators (Common but less definitive)
    "unusual_sections": 8,          # ".crypto", ".locked" sections
    "no_digital_signature": 7,      # Most ransomware lacks valid signatures
    "packer_upx": 6,                # UPX packing (common but not definitive)
    "target_extensions": 6,         # Targeting .docx, .jpg, etc.
    "side_loading_dll": 6,          # DLL hijacking (e.g., "version.dll")
    
    # Contextual Boosters (Compound indicators)
    "suspicious_api_with_scripts": 12, # e.g., CreateFile + PowerShell commands
    "high_entropy_unsigned": 10,    # High entropy + no signature = high risk

    # New Indicators
    "suspicious_extension": 10,     # Suspicious file extensions
    "xor_behavior": 20,             # XOR behavior detection
}

    # Calculate total score
    total_score = 0
    for indicator, value in binary_indicators.items():
        total_score += value * indicator_weights.get(indicator, 0)

    # Add continuous indicators (if needed)
    if continuous_indicators["max_entropy"] > 7.5:
        total_score += 10

    indicators["total_score"] = total_score
    return indicators

def select_directory_and_check():
    directory = filedialog.askdirectory(title="Select Directory")
    if not directory:
        return

    RANSOMWARE_THRESHOLD = 70  # Adjust based on testing

    results = []
    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            if file_path.endswith(".exe"):  # Only process .exe files
                indicators = extract_enhanced_indicators(file_path)
                results.append((file_path, indicators))

    # Display results
    result_text = ""
    for file_path, indicators in results:
        classification = "🚨 RANSOMWARE DETECTED" if indicators["total_score"] >= RANSOMWARE_THRESHOLD else "✅ Likely Safe"
        result_text += f"File: {file_path}\n"
        result_text += f"  Classification: {classification}\n"
        result_text += f"  Total Score: {indicators['total_score']}\n"
        for k, v in indicators.items():
            if k != "total_score":
                result_text += f"  {k}: {v}\n"
        result_text += "\n"

    if result_text:
        result_window = tk.Toplevel()
        result_window.title("Detection Results")
        text_widget = tk.Text(result_window, wrap="word")
        text_widget.insert("1.0", result_text)
        text_widget.config(state="disabled")
        text_widget.pack(expand=True, fill="both")
    else:
        messagebox.showinfo("No Results", "No .exe files found in the selected directory.")

if __name__ == "__main__":
    root = tk.Tk()
    root.title("Static Ransomware Detector")
    root.geometry("400x200")

    label = tk.Label(root, text="Static Ransomware Detector", font=("Arial", 16))
    label.pack(pady=20)

    select_button = tk.Button(root, text="Select Directory", command=select_directory_and_check)
    select_button.pack(pady=10)

    root.mainloop()