import tkinter as tk
from tkinter import messagebox, simpledialog, scrolledtext
import hashlib
import os

# --- Configuration ---
# File to store the encrypted passwords
PASSWORDS_FILE = "passwords.txt"
# File to store the hashed master password
MASTER_HASH_FILE = "master_hash.txt"

# A very simple "encryption" key for this educational project.
# IN REAL APPLICATIONS, DO NOT HARDCODE KEYS LIKE THIS.
# This key is just for demonstration purposes.
ENCRYPTION_KEY_CHAR = 'K' # A single character for simple XOR

# --- Basic Encryption/Decryption Functions (Educational Only, NOT Secure!) ---
def simple_xor_encrypt_decrypt(text, key_char):
    """
    Encrypts or decrypts a string using a simple XOR cipher with a single character key.
    This is for educational purposes only and is NOT cryptographically secure.
    """
    encrypted_text = ""
    key_val = ord(key_char)
    for char in text:
        encrypted_char_val = ord(char) ^ key_val
        encrypted_text += chr(encrypted_char_val)
    return encrypted_text

# --- Master Password Setup and Verification ---
def setup_master_password_logic(password):
    """
    Logic to set a new master password and store its hash.
    Returns True on success, False on failure.
    """
    if not password:
        messagebox.showerror("Error", "Master password cannot be empty.")
        return False

    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    try:
        with open(MASTER_HASH_FILE, "w") as f:
            f.write(hashed_password)
        messagebox.showinfo("Success", "Master password set successfully!")
        return True
    except IOError:
        messagebox.showerror("Error", "Could not write master password file.")
        return False

def verify_master_password_logic(password):
    """
    Logic to verify the entered master password against the stored hash.
    Returns True on success, False on failure.
    """
    if not os.path.exists(MASTER_HASH_FILE):
        # This case should ideally be handled before calling this function
        return False

    try:
        with open(MASTER_HASH_FILE, "r") as f:
            stored_hash = f.read().strip()
    except IOError:
        messagebox.showerror("Error", "Could not read master password file.")
        return False

    entered_hash = hashlib.sha256(password.encode()).hexdigest()
    if entered_hash == stored_hash:
        return True
    else:
        return False

# --- Password Management Functions (integrated with file operations) ---
def load_passwords():
    """
    Loads encrypted password entries from the PASSWORDS_FILE.
    Returns a dictionary of decrypted entries.
    """
    passwords = {}
    if os.path.exists(PASSWORDS_FILE):
        try:
            with open(PASSWORDS_FILE, "r") as f:
                for line in f:
                    encrypted_line = line.strip()
                    if encrypted_line:
                        decrypted_line = simple_xor_encrypt_decrypt(encrypted_line, ENCRYPTION_KEY_CHAR)
                        try:
                            # Using a distinct delimiter ';;' to avoid conflicts with '::' in passwords
                            service, username, password = decrypted_line.split(";;")
                            passwords[service.lower()] = {"username": username, "password": password}
                        except ValueError:
                            # Skip malformed lines, but alert user in console for debugging
                            print(f"Warning: Could not parse line in {PASSWORDS_FILE}: {decrypted_line}")
        except IOError:
            messagebox.showerror("Error", "Could not read passwords file.")
    return passwords

def save_passwords(passwords):
    """
    Encrypts and saves password entries to the PASSWORDS_FILE.
    """
    try:
        with open(PASSWORDS_FILE, "w") as f:
            for service, data in passwords.items():
                # Combine service, username, and password with a distinct delimiter
                line_to_encrypt = f"{service};;{data['username']};;{data['password']}"
                encrypted_line = simple_xor_encrypt_decrypt(line_to_encrypt, ENCRYPTION_KEY_CHAR)
                f.write(encrypted_line + "\n")
    except IOError:
        messagebox.showerror("Error", "Could not write passwords file.")

# --- GUI Application Class ---
class PasswordManagerApp:
    def __init__(self, master):
        self.master = master
        master.title("Simple Password Manager")
        master.geometry("400x300") # Set initial window size
        master.resizable(False, False) # Make window non-resizable for simplicity

        self.passwords = {} # Dictionary to hold password data in memory

        # Determine if master password needs setup or verification
        if not os.path.exists(MASTER_HASH_FILE):
            self.show_setup_screen()
        else:
            self.show_unlock_screen()

    def show_setup_screen(self):
        # Clear existing widgets
        for widget in self.master.winfo_children():
            widget.destroy()

        self.master.title("Set Master Password")
        self.master_password_set = tk.StringVar()
        self.master_password_confirm = tk.StringVar()

        tk.Label(self.master, text="Set New Master Password:", font=('Arial', 12)).pack(pady=10)
        tk.Entry(self.master, textvariable=self.master_password_set, show='*', width=30, font=('Arial', 12)).pack(pady=5)

        tk.Label(self.master, text="Confirm Master Password:", font=('Arial', 12)).pack(pady=10)
        tk.Entry(self.master, textvariable=self.master_password_confirm, show='*', width=30, font=('Arial', 12)).pack(pady=5)

        tk.Button(self.master, text="Set Password", command=self.set_master_password, font=('Arial', 12), bg='#4CAF50', fg='white').pack(pady=20)

    def set_master_password(self):
        password = self.master_password_set.get()
        confirm = self.master_password_confirm.get()

        if password != confirm:
            messagebox.showerror("Error", "Passwords do not match!")
            return

        if setup_master_password_logic(password):
            self.show_main_app()
        else:
            # Error message already shown by setup_master_password_logic
            pass

    def show_unlock_screen(self):
        # Clear existing widgets
        for widget in self.master.winfo_children():
            widget.destroy()

        self.master.title("Unlock Password Manager")
        self.master_password_entry = tk.StringVar()

        tk.Label(self.master, text="Enter Master Password:", font=('Arial', 12)).pack(pady=20)
        tk.Entry(self.master, textvariable=self.master_password_entry, show='*', width=30, font=('Arial', 12)).pack(pady=10)

        tk.Button(self.master, text="Unlock", command=self.unlock_app, font=('Arial', 12), bg='#2196F3', fg='white').pack(pady=20)

        self.unlock_feedback_label = tk.Label(self.master, text="", fg="red")
        self.unlock_feedback_label.pack()

    def unlock_app(self):
        password = self.master_password_entry.get()
        if verify_master_password_logic(password):
            self.show_main_app()
        else:
            self.unlock_feedback_label.config(text="Incorrect master password.")
            self.master_password_entry.set("") # Clear password field

    def show_main_app(self):
        # Clear existing widgets
        for widget in self.master.winfo_children():
            widget.destroy()

        self.master.title("Password Manager")
        self.master.geometry("600x450") # Adjust size for main app
        self.master.resizable(True, True) # Allow resizing for main app

        self.passwords = load_passwords() # Load passwords once unlocked

        # --- Input Frame ---
        input_frame = tk.Frame(self.master, padx=10, pady=10, bd=2, relief="groove")
        input_frame.pack(pady=10)

        tk.Label(input_frame, text="Service:", font=('Arial', 10)).grid(row=0, column=0, padx=5, pady=5, sticky='w')
        self.service_entry = tk.Entry(input_frame, width=40, font=('Arial', 10))
        self.service_entry.grid(row=0, column=1, padx=5, pady=5)

        tk.Label(input_frame, text="Username:", font=('Arial', 10)).grid(row=1, column=0, padx=5, pady=5, sticky='w')
        self.username_entry = tk.Entry(input_frame, width=40, font=('Arial', 10))
        self.username_entry.grid(row=1, column=1, padx=5, pady=5)

        tk.Label(input_frame, text="Password:", font=('Arial', 10)).grid(row=2, column=0, padx=5, pady=5, sticky='w')
        self.password_entry = tk.Entry(input_frame, width=40, font=('Arial', 10)) # Do NOT use show='*' here if you want to see what you type before saving
        self.password_entry.grid(row=2, column=1, padx=5, pady=5)

        # --- Buttons ---
        button_frame = tk.Frame(self.master, pady=5)
        button_frame.pack()

        tk.Button(button_frame, text="Add Password", command=self.add_password_gui, font=('Arial', 10), bg='#007BFF', fg='white').pack(side=tk.LEFT, padx=5)
        tk.Button(button_frame, text="Get Password", command=self.get_password_gui, font=('Arial', 10), bg='#007BFF', fg='white').pack(side=tk.LEFT, padx=5)
        tk.Button(button_frame, text="View All Passwords", command=self.prompt_for_view_all_passwords, font=('Arial', 10), bg='#007BFF', fg='white').pack(side=tk.LEFT, padx=5)
        tk.Button(button_frame, text="Clear Fields", command=self.clear_fields, font=('Arial', 10), bg='#6C757D', fg='white').pack(side=tk.LEFT, padx=5)


        # --- Output/Feedback Area ---
        self.feedback_label = tk.Label(self.master, text="", fg="blue", font=('Arial', 10))
        self.feedback_label.pack(pady=10)

        # A Text widget to display retrieved passwords clearly
        tk.Label(self.master, text="Retrieved Info / Output:", font=('Arial', 10, 'bold')).pack(pady=(0,5))
        self.output_text = scrolledtext.ScrolledText(self.master, width=60, height=8, font=('Courier', 10), wrap=tk.WORD)
        self.output_text.pack(pady=5)
        self.output_text.config(state=tk.DISABLED) # Make it read-only initially

    def clear_fields(self):
        self.service_entry.delete(0, tk.END)
        self.username_entry.delete(0, tk.END)
        self.password_entry.delete(0, tk.END)
        self.feedback_label.config(text="")
        self.output_text.config(state=tk.NORMAL)
        self.output_text.delete(1.0, tk.END)
        self.output_text.config(state=tk.DISABLED)

    def set_feedback(self, message, color="blue"):
        self.feedback_label.config(text=message, fg=color)

    def set_output_text(self, text):
        self.output_text.config(state=tk.NORMAL)
        self.output_text.delete(1.0, tk.END)
        self.output_text.insert(tk.END, text)
        self.output_text.config(state=tk.DISABLED)


    def add_password_gui(self):
        service = self.service_entry.get().strip()
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()

        if not service or not username or not password:
            self.set_feedback("All fields are required!", "red")
            return

        self.passwords[service.lower()] = {"username": username, "password": password}
        save_passwords(self.passwords)
        self.set_feedback(f"Entry for '{service}' added successfully!", "green")
        self.clear_fields() # Clear fields after adding

    def get_password_gui(self):
        service = self.service_entry.get().strip().lower()

        if not service:
            self.set_feedback("Enter a service name to retrieve.", "red")
            return

        if service in self.passwords:
            data = self.passwords[service]
            output = f"--- Details for {service.capitalize()} ---\n"
            output += f"Username: {data['username']}\n"
            output += f"Password: {data['password']}\n"
            output += "------------------------------"
            self.set_output_text(output)
            self.set_feedback(f"Details retrieved for '{service}'.", "blue")
        else:
            self.set_feedback(f"No entry found for service '{service}'.", "red")
            self.set_output_text("No data to display.")

    def prompt_for_view_all_passwords(self):
        """
        Prompts the user to re-enter the master password before showing all entries.
        """
        prompt_window = tk.Toplevel(self.master)
        prompt_window.title("Verify Master Password")
        prompt_window.geometry("300x180")
        prompt_window.transient(self.master) # Make it appear on top of the main window
        prompt_window.grab_set() # Make it modal (user must interact with this window)

        mp_var = tk.StringVar()
        feedback_label = tk.Label(prompt_window, text="", fg="red")

        def check_and_show():
            password = mp_var.get()
            if verify_master_password_logic(password):
                prompt_window.destroy() # Close the prompt window
                self.view_all_passwords_gui() # Show the actual passwords window
            else:
                feedback_label.config(text="Incorrect password.")
                mp_var.set("") # Clear entry

        tk.Label(prompt_window, text="Enter Master Password to View All:", font=('Arial', 10)).pack(pady=10)
        tk.Entry(prompt_window, textvariable=mp_var, show='*', width=25, font=('Arial', 10)).pack(pady=5)
        tk.Button(prompt_window, text="Verify", command=check_and_show, font=('Arial', 10), bg='#28A745', fg='white').pack(pady=10)
        feedback_label.pack()

        # Center the prompt window
        self.master.update_idletasks()
        x = self.master.winfo_x() + (self.master.winfo_width() // 2) - (prompt_window.winfo_width() // 2)
        y = self.master.winfo_y() + (self.master.winfo_height() // 2) - (prompt_window.winfo_height() // 2)
        prompt_window.geometry(f"+{x}+{y}")


    def view_all_passwords_gui(self):
        """
        Displays all stored passwords in a new window.
        This function is now called AFTER master password verification.
        """
        # Create a new top-level window for viewing all passwords
        view_window = tk.Toplevel(self.master)
        view_window.title("All Stored Passwords")
        view_window.geometry("500x400")
        view_window.transient(self.master) # Make it appear on top of the main window
        view_window.grab_set() # Make it modal

        tk.Label(view_window, text="Service | Username | Password", font=('Courier', 10, 'bold')).pack(pady=5)

        # Use ScrolledText for potentially many entries
        all_pass_text = scrolledtext.ScrolledText(view_window, width=70, height=15, font=('Courier', 9), wrap=tk.WORD)
        all_pass_text.pack(padx=10, pady=5)
        all_pass_text.config(state=tk.NORMAL)
        all_pass_text.delete(1.0, tk.END) # Clear previous content

        if not self.passwords:
            all_pass_text.insert(tk.END, "No passwords stored yet.")
        else:
            for service, data in self.passwords.items():
                all_pass_text.insert(tk.END, f"{service.capitalize():<15} | {data['username']:<15} | {data['password']}\n")

        all_pass_text.config(state=tk.DISABLED) # Make it read-only

        tk.Button(view_window, text="Close", command=view_window.destroy, font=('Arial', 10), bg='#DC3545', fg='white').pack(pady=10)

        # Center the new window
        self.master.update_idletasks()
        x = self.master.winfo_x() + (self.master.winfo_width() // 2) - (view_window.winfo_width() // 2)
        y = self.master.winfo_y() + (self.master.winfo_height() // 2) - (view_window.winfo_height() // 2)
        view_window.geometry(f"+{x}+{y}")


# --- Main program execution ---
if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordManagerApp(root)
    root.mainloop() # Start the Tkinter event loop
