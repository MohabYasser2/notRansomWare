import sys
import requests
import os
import tkinter as tk
from tkinter import simpledialog, messagebox

def get_key_from_endpoint(random_path):
    # Extract the script's filename
    script_name = os.path.basename(__file__)

    
    # Construct the key retrieval URL
    key_url = f"https://squirrel-pet-bengal.ngrok-free.app/key/{random_path}"
    
    try:
        # Fetch the key from the server
        response = requests.get(key_url)
        response.raise_for_status()  # Raise an error for HTTP issues
        return response.text
    except Exception as e:
        print(f"Failed to retrieve the key: {e}")
        return None

def main():
    # Create a simple UI to get the random path
    root = tk.Tk()
    root.withdraw()  # Hide the main tkinter window

    random_path = simpledialog.askstring("Input Required", "Enter the random path (password) provided in the email:")
    if not random_path:
        messagebox.showerror("Error", "No path provided. Exiting.")
        return

    # Retrieve the key using the provided random path
    key = get_key_from_endpoint(random_path)
    
    # ADD ENCRYPTION LOGIC HERE
    

if __name__ == "__main__":
    main()
