import tkinter as tk
from tkinter import filedialog, messagebox
import requests, os, uuid, base64, hashlib
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256  # Use PyCryptodome's SHA256 module

SERVER_URL = 'http://127.0.0.1:5000'

def derive_key(passphrase, salt=b'unique_salt', iterations=100_000):
    """Derive a 256-bit key from a passphrase using PBKDF2 with HMAC-SHA256."""
    return PBKDF2(passphrase, salt, dkLen=32, count=iterations, hmac_hash_module=SHA256)

def encrypt_text(plain_text, key):
    """Encrypts a text string using AES-GCM and returns a Base64-encoded string."""
    data = plain_text.encode('utf-8')
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    encrypted = base64.b64encode(cipher.nonce + tag + ciphertext).decode('utf-8')
    return encrypted

def decrypt_text(encrypted_text, key):
    """Decrypts a Base64-encoded string encrypted using AES-GCM."""
    data = base64.b64decode(encrypted_text.encode('utf-8'))
    nonce = data[:16]
    tag = data[16:32]
    ciphertext = data[32:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    plain_text = cipher.decrypt_and_verify(ciphertext, tag)
    return plain_text.decode('utf-8')

def encrypt_file_content(file_path, key):
    """Encrypts file content using AES-GCM and returns the binary blob."""
    with open(file_path, 'rb') as f:
        plaintext = f.read()
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return cipher.nonce + tag + ciphertext

def decrypt_file_content(encrypted_blob, key):
    """Decrypts file content previously encrypted with AES-GCM."""
    nonce = encrypted_blob[:16]
    tag = encrypted_blob[16:32]
    ciphertext = encrypted_blob[32:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext

class ClientGUI:
    def __init__(self, master):
        self.master = master
        master.title("Secure Storage Client")
        self.session = requests.Session()
        self.key = None  # Will be derived after login
        self.files_data = []  # List to hold file metadata returned from server

        # Create a frame for login
        self.login_frame = tk.Frame(master)
        self.login_frame.pack(pady=10)

        tk.Label(self.login_frame, text="Username:").grid(row=0, column=0, sticky="e")
        self.username_entry = tk.Entry(self.login_frame)
        self.username_entry.grid(row=0, column=1)

        tk.Label(self.login_frame, text="Password:").grid(row=1, column=0, sticky="e")
        self.password_entry = tk.Entry(self.login_frame, show="*")
        self.password_entry.grid(row=1, column=1)

        tk.Label(self.login_frame, text="Encryption Passphrase:").grid(row=2, column=0, sticky="e")
        self.passphrase_entry = tk.Entry(self.login_frame, show="*")
        self.passphrase_entry.grid(row=2, column=1)

        # Login button
        self.login_button = tk.Button(self.login_frame, text="Login", command=self.login)
        self.login_button.grid(row=3, column=0, columnspan=2, pady=5)

        # Registration button on login screen
        self.register_button = tk.Button(self.login_frame, text="Register", command=self.open_register_window)
        self.register_button.grid(row=4, column=0, columnspan=2, pady=5)

        # Create a frame for file operations (hidden until login)
        self.main_frame = tk.Frame(master)

        # File upload section
        self.upload_button = tk.Button(self.main_frame, text="Upload File", command=self.upload_file)
        self.upload_button.pack(pady=5)

        # File list section
        self.refresh_button = tk.Button(self.main_frame, text="Refresh File List", command=self.refresh_file_list)
        self.refresh_button.pack(pady=5)

        self.file_listbox = tk.Listbox(self.main_frame, width=80)
        self.file_listbox.pack(pady=5)

        self.download_button = tk.Button(self.main_frame, text="Download Selected", command=self.download_selected_file)
        self.download_button.pack(pady=5)

        # Logout button
        self.logout_button = tk.Button(self.main_frame, text="Logout", command=self.logout)
        self.logout_button.pack(pady=5)

    def login(self):
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()
        passphrase = self.passphrase_entry.get().strip()
        if not username or not password or not passphrase:
            messagebox.showerror("Error", "Please fill in all fields.")
            return
        data = {"username": username, "password": password}
        try:
            response = self.session.post(f"{SERVER_URL}/api/login", json=data)
            resp = response.json()
            if resp.get("status") == "ok":
                messagebox.showinfo("Success", "Logged in successfully!")
                self.key = derive_key(passphrase)
                # Hide login frame and show the main file operations frame
                self.login_frame.pack_forget()
                self.main_frame.pack(pady=10)
                # Automatically refresh file list upon login
                self.refresh_file_list()
            else:
                messagebox.showerror("Login Failed", resp.get("message"))
        except Exception as e:
            messagebox.showerror("Error", f"Exception during login: {e}")

    def open_register_window(self):
        # Create a new window for registration
        reg_window = tk.Toplevel(self.master)
        reg_window.title("User Registration")
        
        tk.Label(reg_window, text="Username:").grid(row=0, column=0, sticky="e")
        username_entry = tk.Entry(reg_window)
        username_entry.grid(row=0, column=1)
        
        tk.Label(reg_window, text="Password:").grid(row=1, column=0, sticky="e")
        password_entry = tk.Entry(reg_window, show="*")
        password_entry.grid(row=1, column=1)
        
        def register_user():
            username = username_entry.get().strip()
            password = password_entry.get().strip()
            if not username or not password:
                messagebox.showerror("Error", "Please fill in all fields.", parent=reg_window)
                return
            data = {"username": username, "password": password}
            try:
                response = self.session.post(f"{SERVER_URL}/api/register", json=data)
                resp = response.json()
                if resp.get("status") == "ok":
                    messagebox.showinfo("Success", "Registration successful! Please log in.", parent=reg_window)
                    reg_window.destroy()
                else:
                    messagebox.showerror("Registration Failed", resp.get("message"), parent=reg_window)
            except Exception as e:
                messagebox.showerror("Error", f"Exception during registration: {e}", parent=reg_window)
        
        tk.Button(reg_window, text="Register", command=register_user).grid(row=2, column=0, columnspan=2, pady=10)

    def logout(self):
        """Logs out from the server and returns to the login screen."""
        try:
            response = self.session.post(f"{SERVER_URL}/api/logout")
            resp = response.json()
            if resp.get("status") == "ok":
                messagebox.showinfo("Logged Out", "You have been logged out.")
            else:
                messagebox.showerror("Error", resp.get("message"))
        except Exception as e:
            messagebox.showerror("Error", f"Exception during logout: {e}")
        # Clear the encryption key and file list
        self.key = None
        self.files_data = []
        # Clear the input fields for security
        self.username_entry.delete(0, tk.END)
        self.password_entry.delete(0, tk.END)
        self.passphrase_entry.delete(0, tk.END)
        # Hide the main operations frame and show the login frame again
        self.main_frame.pack_forget()
        self.login_frame.pack(pady=10)

    def upload_file(self):
        if not self.key:
            messagebox.showerror("Error", "Encryption key not set.")
            return
        file_path = filedialog.askopenfilename()
        if not file_path:
            return
        try:
            # Encrypt file content
            encrypted_content = encrypt_file_content(file_path, self.key)
            # Get the original filename and split it
            original_filename = os.path.basename(file_path)
            name_without_ext, ext = os.path.splitext(original_filename)
            # Encrypt only the filename (without extension)
            encrypted_filename = encrypt_text(name_without_ext, self.key)
            # Generate a random stored filename without extension
            stored_filename = str(uuid.uuid4())
            files = {
                'file': (stored_filename, encrypted_content)
            }
            data = {
                'encrypted_filename': encrypted_filename,
                'stored_filename': stored_filename,
                'file_extension': ext  # Send the extension separately
            }
            response = self.session.post(f"{SERVER_URL}/api/upload_file", files=files, data=data)
            resp = response.json()
            if resp.get("status") == "ok":
                messagebox.showinfo("Success", "File uploaded successfully!")
                self.refresh_file_list()
            else:
                messagebox.showerror("Upload Failed", resp.get("message"))
        except Exception as e:
            messagebox.showerror("Error", f"Exception during file upload: {e}")

    def refresh_file_list(self):
        """Retrieve and display the list of files from the server."""
        try:
            response = self.session.get(f"{SERVER_URL}/api/list_files")
            resp = response.json()
            if resp.get("status") == "ok":
                self.file_listbox.delete(0, tk.END)
                self.files_data = resp.get("files", [])
                # Display each file with decrypted original filename (if possible)
                for file in self.files_data:
                    encrypted_fname = file.get("encrypted_filename")
                    stored_fname = file.get("stored_filename")
                    file_ext = file.get("file_extension", "")
                    try:
                        original_fname = decrypt_text(encrypted_fname, self.key)
                    except Exception as e:
                        original_fname = "Decryption Error"
                    display_text = f"{original_fname}{file_ext}  (ID: {file.get('id')}, Stored: {stored_fname})"
                    self.file_listbox.insert(tk.END, display_text)
            else:
                messagebox.showerror("Error", resp.get("message"))
        except Exception as e:
            messagebox.showerror("Error", f"Exception during refreshing file list: {e}")

    def download_selected_file(self):
        """Download and decrypt the selected file from the server."""
        selection = self.file_listbox.curselection()
        if not selection:
            messagebox.showerror("Error", "No file selected.")
            return
        index = selection[0]
        try:
            file_info = self.files_data[index]
            stored_filename = file_info.get("stored_filename")
            file_ext = file_info.get("file_extension", "")
            response = self.session.get(f"{SERVER_URL}/api/download_file/{stored_filename}")
            if response.status_code == 200:
                encrypted_blob = response.content
                decrypted_content = decrypt_file_content(encrypted_blob, self.key)
                try:
                    decrypted_name = decrypt_text(file_info.get("encrypted_filename"), self.key)
                except Exception:
                    decrypted_name = "downloaded_file"
                default_name = f"{decrypted_name}{file_ext}"
                save_path = filedialog.asksaveasfilename(
                    title="Save File As",
                    initialfile=default_name,
                    defaultextension=file_ext,
                    filetypes=[(f"{file_ext.upper()} files", f"*{file_ext}"), ("All Files", "*.*")]
                )
                if save_path:
                    with open(save_path, 'wb') as f:
                        f.write(decrypted_content)
                    messagebox.showinfo("Success", "File downloaded and decrypted successfully!")
            else:
                resp = response.json()
                messagebox.showerror("Error", resp.get("message", "Download failed"))
        except Exception as e:
            messagebox.showerror("Error", f"Exception during file download: {e}")

if __name__ == '__main__':
    root = tk.Tk()
    gui = ClientGUI(root)
    root.mainloop()
