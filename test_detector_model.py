import os
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import numpy as np
import pandas as pd
import joblib
import pefile
import re

# Load the trained model
model = joblib.load("ransomware_model.pkl")

# Extract features from a PE file
def extract_features(pe_file):
    try:
        pe = pefile.PE(pe_file)

        # Static PE structure features
        features = {
            "entry_point": pe.OPTIONAL_HEADER.AddressOfEntryPoint,
            "image_base": pe.OPTIONAL_HEADER.ImageBase,
            "section_count": len(pe.sections),
            "dll_characteristics": pe.OPTIONAL_HEADER.DllCharacteristics,
            "timestamp": pe.FILE_HEADER.TimeDateStamp,
            "is_executable": pe_file.endswith('.exe'),  # Check if the file extension is .exe
            "is_dll": pe.is_dll(),
            "has_imports": len(pe.DIRECTORY_ENTRY_IMPORT) > 0 if hasattr(pe, "DIRECTORY_ENTRY_IMPORT") else 0,
            "has_exports": len(pe.DIRECTORY_ENTRY_EXPORT.symbols) > 0 if hasattr(pe, "DIRECTORY_ENTRY_EXPORT") else 0,
            "is_64bit": pe.FILE_HEADER.Machine == 0x8664,
        }

        # Behavioral features
        with open(pe_file, "rb") as f:
            data = f.read().lower()

        def contains_any(keywords):
            return any(kw.encode() in data for kw in keywords)

        features["uses_crypto_apis"] = contains_any([
            "aes", "rsa", "des", "blowfish", "twofish", "serpent",
            "cryptencrypt", "cryptdecrypt", "cryptimportkey", "cryptacquirecontext"
        ])
        features["deletes_shadow_copies"] = b"vssadmin delete shadows" in data
        features["modifies_registry"] = b"reg add" in data or b"reg delete" in data
        features["network_activity"] = any(proto in data for proto in [b"http://", b"https://", b"ftp://"])
        features["has_suspicious_commands"] = contains_any(["cmd.exe", "powershell", "schtasks", "taskkill", "attrib"])
        features["contains_ransom_note"] = contains_any(["ransom", "decrypt", "bitcoin", "payment"])

        # Fix for 'ResourceDirEntryData' object has no attribute 'Data'
        if hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
            features["has_large_resources"] = any(
                hasattr(entry, "data") and entry.data.struct.Size > 1000000
                for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries
                if hasattr(entry, "data")
            )
        else:
            features["has_large_resources"] = False

        # Fix for 'bool' object is not iterable
        features["has_embedded_pe"] = b"MZ" in data and b"PE" in data  # Check for embedded PE files

        features["has_suspicious_sections"] = any(
            section.Name.decode().strip() in [".text", ".data", ".rsrc"] and section.SizeOfRawData == 0
            for section in pe.sections
        )
        features["has_high_entropy"] = any(
            section.get_entropy() > 7.9 for section in pe.sections
        )
        features["has_large_code_section"] = any(
            section.Name.decode().strip() == ".text" and section.Misc_VirtualSize > 1000000
            for section in pe.sections
        )
        features["has_ransom_strings"] = contains_any([
            "ransom", "decrypt", "payment", "locked", "encrypt", "extortion", "wallet", "pay", "bitcoin", "keylogger", "malware"
        ])
        features["has_hardcoded_ips"] = bool(re.search(rb'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', data))
        features["has_hardcoded_urls"] = bool(re.search(rb'https?://[^\s/$.?#].[^\s]*', data))
        features["has_crypto_constants"] = bool(re.search(
            rb'\x30\x82[\x00-\xFF]{2}\x02\x82[\x00-\xFF]{2}\x00[\x00-\xFF]{128,}', data
        )) or bool(re.search(
            rb'\x63\x7c\x77\x7b\xf2\x6b\x6f\xc5\x30\x01\x67\x2b\xfe\xd7\xab\x76', data
        ))
        features["has_hardcoded_commands"] = contains_any([
            "vssadmin delete shadows", "bcdedit /set {default} recoveryenabled no", "cipher /w",
            "wbadmin delete catalog", "schtasks /delete /tn", "taskkill /f /im", "icacls", "takeown /f",
            "attrib +h +s", "del /f /q", "net stop", "netsh advfirewall set allprofiles state off",
            "powershell -command Remove-Item", "wmic shadowcopy delete", "bcdedit /set safeboot minimal"
        ])
        features["has_hardcoded_paths"] = bool(re.search(
            rb'([a-zA-Z]:\\(?:[a-zA-Z0-9._\-\\ ]+\\)*[a-zA-Z0-9._\- ]+)|(\.\.?\\(?:[a-zA-Z0-9._\-\\ ]+\\)*[a-zA-Z0-9._\- ]+)', data
        ))

        return list(features.values())
    except Exception as e:
        print(f"Error processing {pe_file}: {e}")
        return None

# Predict whether a file is ransomware or not
def predict_ransomware(pe_file):
    features = extract_features(pe_file)
    if features is None:
        return "Error"
    vector = np.array(features).reshape(1, -1)
    prediction = model.predict(vector)
    return "Ransomware" if prediction[0] == 1 else "Benign"

# Scan a folder recursively
def scan_folder(folder):
    results = []

    # Initialize progress bar
    root = tk.Tk()
    root.title("Scanning Progress")
    progress = ttk.Progressbar(root, orient="horizontal", length=400, mode="determinate")
    progress.pack(pady=20)
    progress_label = tk.Label(root, text="Scanning files...", font=("Arial", 10))
    progress_label.pack()
    root.update()

    # Count total .exe files
    total_files = sum(len(files) for _, _, files in os.walk(folder) if any(f.endswith(".exe") for f in files))
    progress["maximum"] = total_files
    progress["value"] = 0

    for root_dir, _, files in os.walk(folder):
        for file in files:
            if file.endswith(".exe"):
                full_path = os.path.join(root_dir, file)
                verdict = predict_ransomware(full_path)
                results.append({"File": full_path, "Prediction": verdict})
                progress["value"] += 1
                progress_label.config(text=f"Scanning: {file} ({progress['value']}/{total_files})")
                root.update()

    root.destroy()  # Close the progress bar window
    return results

# Export results to Excel
def save_to_excel(data, output_path):
    df = pd.DataFrame(data)
    df.to_excel(output_path, index=False)
    return output_path

# GUI callback
def browse_and_scan():
    folder = filedialog.askdirectory(title="Select Folder to Scan")
    if not folder:
        return

    results = scan_folder(folder)
    if not results:
        messagebox.showinfo("No Files", "No .exe files found in the selected folder.")
        return

    for row in tree.get_children():
        tree.delete(row)

    ransomware_count = 0
    for item in results:
        is_ransom = item['Prediction'] == "Ransomware"
        if is_ransom:
            ransomware_count += 1
        tree.insert("", "end", values=(item["File"], item["Prediction"]))

    summary_label.config(text=f"Total Files: {len(results)} | Ransomware Detected: {ransomware_count}")

    excel_path = os.path.join(folder, "ransomware_scan_results.xlsx")
    save_to_excel(results, excel_path)
    messagebox.showinfo("Scan Complete", f"{len(results)} files scanned.\nExcel saved to:\n{excel_path}")

# GUI setup
root = tk.Tk()
root.title("Ransomware Detector (ML-Based)")
root.geometry("900x600")

# Header and scan button
tk.Button(root, text="Select Folder to Scan", command=browse_and_scan, font=("Arial", 12)).pack(pady=10)

# Summary Label
summary_label = tk.Label(root, text="Total Files: 0 | Ransomware Detected: 0", font=("Arial", 11, "bold"))
summary_label.pack()

# Table to display results
tree = ttk.Treeview(root, columns=("File", "Prediction"), show="headings")
tree.heading("File", text="File")
tree.heading("Prediction", text="Prediction")
tree.column("File", width=600)
tree.column("Prediction", width=150)
tree.pack(expand=True, fill="both", padx=10, pady=10)

# Start the main loop
root.mainloop()
