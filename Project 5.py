from cryptography.fernet import Fernet
import re
import tkinter as tk
from tkinter import messagebox

# Functions for password manager

def is_strong_password(password):
    # Password strength criteria:
    # At least 8 characters long
    # Contains at least one uppercase letter
    # Contains at least one lowercase letter
    # Contains at least one digit
    # Contains at least one special character
    pattern = r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$"
    return re.match(pattern, password)

def add_password():
    name = account_name_entry.get()
    pwd = password_entry.get()

    if not is_strong_password(pwd):
        messagebox.showerror("Weak Password", "Password does not meet the criteria for strength.")
        return

    with open('passwords.txt', 'a') as f:
        encrypted_pwd = fer.encrypt(pwd.encode()).decode()
        f.write(name + "|" + encrypted_pwd + "\n")
    
    messagebox.showinfo("Success", "Password added successfully.")
    account_name_entry.delete(0, tk.END)
    password_entry.delete(0, tk.END)

def view_passwords():
    try:
        with open('passwords.txt', 'r') as f:
            passwords = f.readlines()
            if not passwords:
                messagebox.showinfo("No Passwords", "No passwords found.")
            else:
                passwords_window = tk.Toplevel(root)
                passwords_window.title("View Passwords")
                
                text_box = tk.Text(passwords_window, height=20, width=40)
                text_box.pack()
                
                for line in passwords:
                    data = line.rstrip()
                    user, passw = data.split("|")
                    decrypted_password = fer.decrypt(passw.encode()).decode()
                    text_box.insert(tk.END, f"User: {user} | Password: {decrypted_password}\n")
    except FileNotFoundError:
        messagebox.showinfo("No Passwords", "No passwords found.")

def load_key():
    try:
        with open("key.key", "rb") as key_file:
            return key_file.read()
    except FileNotFoundError:
        return Fernet.generate_key()

# GUI setup
root = tk.Tk()
root.title("Password Manager")

# Load encryption key
key = load_key()
fer = Fernet(key)

# Account Name Label and Entry
account_name_label = tk.Label(root, text="Account Name:")
account_name_label.pack()
account_name_entry = tk.Entry(root)
account_name_entry.pack()

# Password Label and Entry
password_label = tk.Label(root, text="Password:")
password_label.pack()
password_entry = tk.Entry(root, show="*")
password_entry.pack()

# Add Password Button
add_button = tk.Button(root, text="Add Password", command=add_password)
add_button.pack()

# View Passwords Button
view_button = tk.Button(root, text="View Passwords", command=view_passwords)
view_button.pack()

# Run the main event loop
root.mainloop()
