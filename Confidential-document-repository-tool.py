import os
import json
import base64
import tkinter as tk
from tkinter import simpledialog, messagebox, filedialog
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

LEGAL_KEY = b'legal_key_123456'
FAKE_KEY = b'fake_key_123456'
ADMIN_KEY = b'admin_key_123456'
# 使用绝对路径指定用户数据 JSON 文件路径
USER_DATA_FILE = os.path.abspath(os.path.join(os.getcwd(), '../user_data.json'))

class File:
    def __init__(self, name, content, is_fake=False):
        self.name = name
        self.is_fake = is_fake
        self.encrypted_content = self.encrypt(content, is_fake)
    
    def encrypt(self, content, is_fake):
        key = LEGAL_KEY if not is_fake else FAKE_KEY
        
        cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_content = padder.update(content.encode('utf-8')) + padder.finalize()
        encrypted_content = encryptor.update(padded_content) + encryptor.finalize()
        return base64.b64encode(encrypted_content).decode('utf-8')
    
    def decrypt(self, key):
        cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_content = decryptor.update(base64.b64decode(self.encrypted_content)) + decryptor.finalize()
        unpadded_content = self.unpad(decrypted_content)
        return unpadded_content.decode('utf-8')
    
    def unpad(self, data):
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        return unpadder.update(data) + unpadder.finalize()

class FileVault:
    def __init__(self):
        self.files = []
        self.user_files = {}
        self.user_keys = {}
        self.load_user_data()

    def add_file(self, username, name, content, is_fake=False):
        if username not in self.user_files:
            self.user_files[username] = []
        file = File(name, content, is_fake)
        self.user_files[username].append(file)
        print(f"File '{name}' added to the vault for user '{username}'.")

    def remove_file(self, username, name):
        if username in self.user_files:
            self.user_files[username] = [file for file in self.user_files[username] if file.name != name]
            print(f"File '{name}' removed from the vault for user '{username}'.")
    
    def list_files(self, username):
        if username in self.user_files:
            return [file.name for file in self.user_files[username]]
        return []
    
    def view_file(self, username, name ,key):
       
        # key1 = LEGAL_KEY
        if username in self.user_files:
            for file in self.user_files[username]:
                if file.name == name:
                    try:
                        return file.decrypt(key)
                    except Exception as e:
                        return "This is the 100000th secret message."
        return "File not found."
    
    def set_user_key(self, username, key):
        self.user_keys[username] = key
        self.save_user_data()

    def save_user_data(self):
        data = {'user_keys': {k: v.decode('utf-8') for k, v in self.user_keys.items()}}
        with open(USER_DATA_FILE, 'w') as f:
            json.dump(data, f)

    def load_user_data(self):
        if os.path.exists(USER_DATA_FILE):
            try:
                with open(USER_DATA_FILE, 'r') as f:
                    data = json.load(f)
                    self.user_keys = {k: v.encode('utf-8') for k, v in data['user_keys'].items()}
            except json.JSONDecodeError:
                print("Failed to load user data: Invalid JSON format")
                self.user_keys = {}

class FileVaultApp:
    def __init__(self, root):
        self.vault = FileVault()
        self.key = None
        self.username = None
        self.is_admin = False
        self.is_legal_user = False
        
        self.root = root
        self.main_menu()

    def main_menu(self):
        for widget in self.root.winfo_children():
            widget.destroy()

        self.root.title("Secure File Vault")
        self.root.geometry("400x300")

        self.role = simpledialog.askstring("Role Selection", "Enter your role (user/admin):")
        if not self.role:
            self.root.destroy()
            return
        
        self.username_entry = simpledialog.askstring("Login", "Enter your username:")
        self.key_entry = simpledialog.askstring("Authentication", "Enter your key:", show='*')
        if not self.username_entry or not self.key_entry:
            self.root.destroy()
            return

        self.username = self.username_entry
        self.key = self.key_entry.encode('utf-8')
        
        if self.role == 'admin' and self.key == ADMIN_KEY:
            self.is_admin = True
        elif self.role == 'user' and self.vault.user_keys.get(self.username) == self.key:
            self.is_legal_user = True

        # if not self.is_admin and not self.is_legal_user:
        #     messagebox.showerror("Error", "Invalid key or role.")
        #     self.root.destroy()
        #     return

        self.frame = tk.Frame(self.root)
        self.frame.pack(pady=20)

        self.add_btn = tk.Button(self.frame, text="Add File", command=self.add_file)
        self.add_btn.grid(row=0, column=0, padx=10)
        
        self.remove_btn = tk.Button(self.frame, text="Remove File", command=self.remove_file)
        self.remove_btn.grid(row=0, column=1, padx=10)

        self.list_btn = tk.Button(self.frame, text="List Files", command=self.list_files)
        self.list_btn.grid(row=0, column=2, padx=10)
        
        self.view_btn = tk.Button(self.frame, text="View File", command=self.view_file)
        self.view_btn.grid(row=0, column=3, padx=10)

        if self.is_admin:
            self.add_user_btn = tk.Button(self.frame, text="Add User", command=self.add_user)
            self.add_user_btn.grid(row=0, column=4, padx=10)
            self.view_users_btn = tk.Button(self.frame, text="View Users", command=self.view_users)
            self.view_users_btn.grid(row=0, column=5, padx=10)
        
        self.exit_btn = tk.Button(self.frame, text="Exit", command=self.exit)
        self.exit_btn.grid(row=0, column=6, padx=10)

        self.file_list = tk.Listbox(self.root)
        self.file_list.pack(pady=10, fill=tk.BOTH, expand=True)
        
        # 预存三个文件
        self.prepopulate_files()
        self.list_files()

    def prepopulate_files(self):
        self.vault.add_file(self.username, "secret1.txt", "This is the first secret message.")
        self.vault.add_file(self.username, "secret2.txt", "This is the second secret message.")
        self.vault.add_file(self.username, "secret3.txt", "This is the third secret message.")

    def add_file(self):
        if not self.is_legal_user and not self.is_admin:
            messagebox.showerror("Error", "Illegal user cannot add files.")
            return
        
        file_path = filedialog.askopenfilename()
        if file_path:
            try:
                with open(file_path, 'r', encoding='utf-8') as file:
                    content = file.read()
                file_name = os.path.basename(file_path)
                self.vault.add_file(self.username, file_name, content)
                self.list_files()
            except UnicodeDecodeError:
                messagebox.showerror("Error", "Failed to read the file. Unsupported encoding.")
    
    def remove_file(self):
        if not self.is_legal_user and not self.is_admin:
            messagebox.showerror("Error", "Illegal user cannot remove files.")
            return
        
        selected_file = self.file_list.get(tk.ACTIVE)
        if selected_file:
            self.vault.remove_file(self.username, selected_file)
            self.list_files()

    def list_files(self):
        self.file_list.delete(0, tk.END)
        files = self.vault.list_files(self.username)
        for file in files:
            self.file_list.insert(tk.END, file)

    def view_file(self):
        selected_file = self.file_list.get(tk.ACTIVE)
        if selected_file:
            if not self.is_legal_user:
                content = self.vault.view_file(self.username, selected_file, FAKE_KEY)
            else:
                content = self.vault.view_file(self.username, selected_file, self.key)
            messagebox.showinfo("File Content", content)
    
    def add_user(self):
        if not self.is_admin:
            messagebox.showerror("Error", "Only admin can add users.")
            return

        new_username = simpledialog.askstring("Add User", "Enter new username:")
        new_user_key = simpledialog.askstring("Set Key", "Enter key for new user:", show='*')
        if new_username and new_user_key:
            self.vault.set_user_key(new_username, new_user_key.encode('utf-8'))
            messagebox.showinfo("Success", f"User '{new_username}' added with key.")

    def view_users(self):
        if not self.is_admin:
            messagebox.showerror("Error", "Only admin can view users.")
            return
        
        users = self.vault.user_keys
        user_list = "\n".join([f"{username}: {'*' * len(key.decode('utf-8'))}" for username, key in users.items()])
        messagebox.showinfo("User List", user_list)
    
    def exit(self):
        self.root.destroy()
        self.__init__(self.root)

if __name__ == "__main__":
    root = tk.Tk()
    app = FileVaultApp(root)
    root.mainloop()
