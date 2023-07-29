from cryptography.fernet import Fernet
import re
import tkinter as tk
from tkinter import messagebox

def is_strong_password(password):
    pattern = r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$"
    return re.match(pattern, password)

def authenticate(username, password):
    valid_username = "user123"
    valid_password = "P@ssw0rd"
    return username == valid_username and password == valid_password

def register():
    username = reg_username_entry.get()
    password = reg_password_entry.get()
    interspace = interspace_entry.get()

    if not is_strong_password(password):
        messagebox.showerror("Weak Password", "Password does not meet the criteria for strength.")
        return

    print(f"New User Registration:\nUsername: {username}\nPassword: {password}\nInterspace: {interspace}")
    messagebox.showinfo("Success", "Registration successful. You can now log in.")
    clear_registration_fields()

def clear_registration_fields():
    reg_username_entry.delete(0, tk.END)
    reg_password_entry.delete(0, tk.END)
    interspace_entry.delete(0, tk.END)

def interspace_recovery():
    interspace = "Your interspace is the name of your first pet."
    messagebox.showinfo("Interspace Recovery", interspace)

def add_password():
    name = account_name_entry.get()
    pwd = password_entry.get()

    if not is_strong_password(pwd):
        messagebox.showerror("Weak Password", "Password does not meet the criteria for strength.")
        return

    with open('passwords.txt', 'a') as f:
        f.write(name + "|" + fer.encrypt(pwd.encode()).decode() + "\n")
    
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

def generate_new_key():
    return Fernet.generate_key()

def load_key():
    try:
        with open('key.key', 'rb') as key_file:
            key = key_file.read()
    except FileNotFoundError:
        key = generate_new_key()
        with open('key.key', 'wb') as key_file:
            key_file.write(key)
    return key

root = tk.Tk()
root.title("Password Manager")

key = load_key()
fer = Fernet(key)

logged_in_frame = tk.Frame(root)
logged_in_frame.pack()

username_label = tk.Label(logged_in_frame, text="Username:")
username_label.pack()
username_entry = tk.Entry(logged_in_frame)
username_entry.pack()

password_label = tk.Label(logged_in_frame, text="Password:")
password_label.pack()
password_entry = tk.Entry(logged_in_frame, show="*")
password_entry.pack()

def login():
    username = username_entry.get()
    password = password_entry.get()

    if authenticate(username, password):
        logged_in_frame.pack_forget()
        main_frame.pack()
    else:
        messagebox.showerror("Authentication Failed", "Invalid username or password.")
        username_entry.delete(0, tk.END)
        password_entry.delete(0, tk.END)

login_button = tk.Button(logged_in_frame, text="Login", command=login)
login_button.pack()

main_frame = tk.Frame(root)

account_name_label = tk.Label(main_frame, text="Account Name:")
account_name_label.pack()
account_name_entry = tk.Entry(main_frame)
account_name_entry.pack()

password_label = tk.Label(main_frame, text="Password:")
password_label.pack()
password_entry = tk.Entry(main_frame, show="*")
password_entry.pack()

add_button = tk.Button(main_frame, text="Add Password", command=add_password)
add_button.pack()

view_button = tk.Button(main_frame, text="View Passwords", command=view_passwords)
view_button.pack()

main_frame.pack_forget()

reg_frame = tk.Frame(root)

reg_username_label = tk.Label(reg_frame, text="Username:")
reg_username_label.pack()
reg_username_entry = tk.Entry(reg_frame)
reg_username_entry.pack()

reg_password_label = tk.Label(reg_frame, text="Password:")
reg_password_label.pack()
reg_password_entry = tk.Entry(reg_frame, show="*")
reg_password_entry.pack()

interspace_label = tk.Label(reg_frame, text="Interspace:")
interspace_label.pack()
interspace_entry = tk.Entry(reg_frame)
interspace_entry.pack()

register_button = tk.Button(reg_frame, text="Register", command=register)
register_button.pack()

reg_frame.pack_forget()

interspace_frame = tk.Frame(root)

interspace_label_recovery = tk.Label(interspace_frame, text="Interspace Recovery:")
interspace_label_recovery.pack()
interspace_entry_recovery = tk.Entry(interspace_frame)
interspace_entry_recovery.pack()

recover_interspace_button = tk.Button(interspace_frame, text="Recover Interspace", command=interspace_recovery)
recover_interspace_button.pack()

interspace_frame.pack_forget()

def show_registration_frame():
    logged_in_frame.pack_forget()
    main_frame.pack_forget()
    interspace_frame.pack_forget()
    reg_frame.pack()

def show_login_frame():
    reg_frame.pack_forget()
    main_frame.pack_forget()
    interspace_frame.pack_forget()
    logged_in_frame.pack()

def show_interspace_frame():
    reg_frame.pack_forget()
    logged_in_frame.pack_forget()
    main_frame.pack_forget()
    interspace_frame.pack()

choice_label = tk.Label(root, text="Choose:")
choice_label.pack()

login_choice_button = tk.Button(root, text="Login", command=show_login_frame)
login_choice_button.pack()

register_choice_button = tk.Button(root, text="Register", command=show_registration_frame)
register_choice_button.pack()

interspace_choice_button = tk.Button(root, text="Interspace Recovery", command=show_interspace_frame)
interspace_choice_button.pack()

root.mainloop()
