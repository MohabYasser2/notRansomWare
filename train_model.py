import os
import pefile
import numpy as np
import joblib
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
import re  # Add import for regex
import tkinter as tk
from tkinter import filedialog
from tkinter import ttk  # Import ttk for progress bar
import magic  # Add import for magic library

# Step 1: Extract combined features
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

        

        return features
    except Exception as e:
        print(f"Error processing {pe_file}: {e}")
        return None


# Step 2: Get file paths and labels
def create_feature_matrix_from_directories(ransomware_dir, benign_dir):
    file_paths = []
    labels = []
    executable_mime_types = [
        "application/x-dosexec",  # For PE executables
        "application/vnd.microsoft.portable-executable",  # Alternate MIME for PE files
        "application/x-msdownload"  # Common MIME for Windows executables
    ]

    for filename in os.listdir(ransomware_dir):
        full_path = os.path.join(ransomware_dir, filename)
        mime_type = magic.Magic(mime=True).from_file(full_path)
        if mime_type in executable_mime_types:
            file_paths.append(full_path)
            labels.append(1)

    for filename in os.listdir(benign_dir):
        full_path = os.path.join(benign_dir, filename)
        mime_type = magic.Magic(mime=True).from_file(full_path)
        if mime_type in executable_mime_types:
            file_paths.append(full_path)
            labels.append(0)

    return file_paths, labels


# Step 3: Create feature matrix and label array
def create_feature_matrix(file_paths, labels):
    features_list = []
    valid_labels = []

    # Initialize progress bar
    root = tk.Tk()
    root.title("Feature Extraction Progress")
    progress = ttk.Progressbar(root, orient="horizontal", length=300, mode="determinate")
    progress.pack(pady=20)
    progress["maximum"] = len(file_paths)
    progress["value"] = 0
    tk.Label(root, text="Extracting features...").pack()
    root.update()

    for i, (path, label) in enumerate(zip(file_paths, labels)):
        features = extract_features(path)
        if features:
            features_list.append(list(features.values()))
            valid_labels.append(label)
        progress["value"] = i + 1
        root.update()

    root.destroy()  # Close the progress bar window
    return np.array(features_list), np.array(valid_labels)


# Step 4: Load and process dataset
def select_directories():
    root = tk.Tk()
    root.withdraw()  # Hide the root window

    print("Select the directory containing ransomware files:")
    ransomware_dir = filedialog.askdirectory(title="Select Ransomware Directory")
    print(f"Ransomware directory selected: {ransomware_dir}")

    print("Select the directory containing benign files:")
    benign_dir = filedialog.askdirectory(title="Select Benign Directory")
    print(f"Benign directory selected: {benign_dir}")

    return ransomware_dir, benign_dir

ransomware_dir, benign_dir = select_directories()

file_paths, labels = create_feature_matrix_from_directories(ransomware_dir, benign_dir)
X, y = create_feature_matrix(file_paths, labels)

# Step 5: Split dataset
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Step 6: Train model
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# Step 7: Evaluate model
y_pred = model.predict(X_test)
print("Classification Report:")
print(classification_report(y_test, y_pred))

# Step 8: Save model
joblib.dump(model, 'ransomware_model.pkl')

# Step 9: Load model
loaded_model = joblib.load('ransomware_model.pkl')


# Step 10: Predict a new file
def predict_ransomware(pe_file, model):
    features = extract_features(pe_file)
    if not features:
        return "Error during prediction"
    feature_vector = np.array(list(features.values())).reshape(1, -1)
    prediction = model.predict(feature_vector)
    return "Ransomware" if prediction == 1 else "Benign"


# # Step 11: Run prediction
# pe_file = 'path/to/new_file.exe'  # Update this path
# result = predict_ransomware(pe_file, loaded_model)
# print(f"Prediction for {pe_file}: {result}")