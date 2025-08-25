import tkinter as tk
import pyotp
import time
import os
import base64
from cryptography.fernet import Fernet

# Secure key handling helpers
SECRET_FILE = "secrets.enc"   # encrypted secrets storage
KEY_FILE = "key.key"          # encryption key storage


def generate_key():
    """Generate a new Fernet key if not exists."""
    if not os.path.exists(KEY_FILE):
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as f:
            f.write(key)


def load_key():
    """Load the encryption key."""
    with open(KEY_FILE, "rb") as f:
        return f.read()


def encrypt_secret(secret: str) -> bytes:
    """Encrypt the secret key before saving."""
    f = Fernet(load_key())
    return f.encrypt(secret.encode())


def decrypt_secret(encrypted_secret: bytes) -> str:
    """Decrypt the secret key when loading."""
    f = Fernet(load_key())
    return f.decrypt(encrypted_secret).decode()


def save_secret(account: str, secret: str):
    """Append account and encrypted secret to file."""
    enc_secret = encrypt_secret(secret)
    with open(SECRET_FILE, "ab") as f:
        f.write(account.encode() + b":" + enc_secret + b"\n")


def save_all_secrets(secrets: dict):
    """Overwrite secrets.enc with current accounts."""
    with open(SECRET_FILE, "wb") as f:
        for account, secret in secrets.items():
            enc_secret = encrypt_secret(secret)
            f.write(account.encode() + b":" + enc_secret + b"\n")


def load_secrets():
    """Load all saved accounts and their decrypted secrets."""
    secrets = {}
    if os.path.exists(SECRET_FILE):
        with open(SECRET_FILE, "rb") as f:
            for line in f:
                if b":" in line:
                    account, enc_secret = line.strip().split(b":", 1)
                    try:
                        secrets[account.decode()] = decrypt_secret(enc_secret)
                    except Exception:
                        pass
    return secrets


# GUI & TOTP Logic
class TOTPApp:
    def __init__(self, root):
        self.root = root
        self.root.title("NullPass Authenticator")
        self.root.configure(bg="#1E1E2E")
        self.root.geometry("600x400")

        self.container = tk.Frame(root, bg="#1E1E2E")
        self.container.pack(fill="both", expand=True)

        self.accounts = load_secrets()
        self.labels = {}

        self.show_main_screen()
        self.update_totps()

    def clear_container(self):
        """Remove all widgets from container."""
        for widget in self.container.winfo_children():
            widget.destroy()

    def show_main_screen(self):
        """Main screen with codes list + add button."""
        self.clear_container()
        self.labels.clear()

        # Title
        title = tk.Label(self.container, text="Verification Codes",
                         fg="white", bg="#1E1E2E", font=("Arial", 16, "bold"))
        title.pack(pady=10)

        # Frame for accounts list
        self.codes_frame = tk.Frame(self.container, bg="#1E1E2E")
        self.codes_frame.pack(fill="both", expand=True, padx=10)

        # Add Account button
        add_btn = tk.Button(self.container, text="➕ Add Account Key", command=self.show_add_account_screen,
                            bg="gray30", fg="white", font=("Arial", 12))
        add_btn.pack(pady=10)

        for acc, secret in self.accounts.items():
            self.add_account_to_ui(acc, secret)

    def show_add_account_screen(self):
        """Screen for adding a new TOTP account (inline, no popup)."""
        self.clear_container()

        # Cancel button
        cancel_btn = tk.Button(self.container, text="X", command=self.show_main_screen,
                               bg="red", fg="white", font=("Arial", 10, "bold"))
        cancel_btn.pack(anchor="ne", padx=5, pady=5)

        lbl = tk.Label(self.container, text="Create Verification Code",
                       fg="white", bg="#1E1E2E", font=("Arial", 14, "bold"))
        lbl.pack(pady=5)

        # Error label
        error_label = tk.Label(self.container, text="", fg="red", bg="#1E1E2E", font=("Arial", 10))
        error_label.pack(pady=5)

        # Placeholder helper
        def add_placeholder(entry, placeholder, is_secret=False):
            entry.insert(0, placeholder)
            entry.config(fg="gray")
            if is_secret:
                entry.config(show="")  # always show placeholder normally

            def on_focus_in(event):
                if entry.get() == placeholder:
                    entry.delete(0, tk.END)
                    entry.config(fg="white")
                    if is_secret and eye_btn.cget("text") == "👁️":
                        entry.config(show="*")  # mask when user types

            def on_focus_out(event):
                if not entry.get():
                    entry.insert(0, placeholder)
                    entry.config(fg="gray")
                    if is_secret:
                        entry.config(show="")  # show placeholder unmasked

            entry.bind("<FocusIn>", on_focus_in)
            entry.bind("<FocusOut>", on_focus_out)

        # Account name field
        tk.Label(self.container, text="Name", fg="white", bg="#1E1E2E").pack(pady=(10, 2))
        account_entry = tk.Entry(self.container, bg="gray20", fg="white", insertbackground="white")
        account_entry.pack(pady=2, padx=20, fill="x")
        add_placeholder(account_entry, "Name")

        # Secret key field with eye toggle
        tk.Label(self.container, text="Key", fg="white", bg="#1E1E2E").pack(pady=(10, 2))
        key_frame = tk.Frame(self.container, bg="#1E1E2E")
        key_frame.pack(pady=2, padx=20, fill="x")

        secret_entry = tk.Entry(key_frame, bg="gray20", fg="white", insertbackground="white")
        secret_entry.pack(side="left", fill="x", expand=True)

        def toggle_secret():
            if secret_entry.cget("show") == "":
                secret_entry.config(show="*")
                eye_btn.config(text="🙈")
            else:
                secret_entry.config(show="")
                eye_btn.config(text="👁️")

        eye_btn = tk.Button(key_frame, text="👁️", command=toggle_secret,
                            bg="gray30", fg="white", width=3)
        eye_btn.pack(side="right", padx=5)

        add_placeholder(secret_entry, "Key", is_secret=True)

        # Save button
        def save_and_close():
            account = account_entry.get().strip()
            secret = secret_entry.get().strip().replace(" ", "")
            error_label.config(text="")  # clear error first

            if not account or account == "Name" or not secret or secret == "Key":
                error_label.config(text="Both Name and Key are required.")
                return

            try:
                base64.b32decode(secret, casefold=True)
                pyotp.TOTP(secret).now()
            except Exception:
                error_label.config(text="Invalid Secret Key format.")
                return

            self.accounts[account] = secret
            save_secret(account, secret)
            self.show_main_screen()

        save_btn = tk.Button(self.container, text="ADD Code", command=save_and_close,
                             bg="green", fg="white", font=("Arial", 12))
        save_btn.pack(pady=20)

    def show_delete_confirmation(self, account):
        """Inline confirmation for deleting an account."""
        self.clear_container()

        lbl = tk.Label(self.container, text=f"Remove {account}?",
                       fg="white", bg="#1E1E2E", font=("Arial", 14, "bold"))
        lbl.pack(pady=20)

        btn_frame = tk.Frame(self.container, bg="#1E1E2E")
        btn_frame.pack(pady=10)

        def confirm_delete():
            if account in self.accounts:
                del self.accounts[account]
            if account in self.labels:
                del self.labels[account]
            save_all_secrets(self.accounts)
            self.show_main_screen()

        yes_btn = tk.Button(btn_frame, text="Yes", command=confirm_delete,
                            bg="red", fg="white", font=("Arial", 12, "bold"), width=8)
        yes_btn.grid(row=0, column=0, padx=10)

        no_btn = tk.Button(btn_frame, text="No", command=self.show_main_screen,
                           bg="gray30", fg="white", font=("Arial", 12), width=8)
        no_btn.grid(row=0, column=1, padx=10)

    def add_account_to_ui(self, account, secret):
        """Add a row for an account in the main window."""
        frame = tk.Frame(self.codes_frame, bg="#1E1E2E")
        frame.pack(fill="x", pady=5)

        frame.grid_columnconfigure(0, weight=1)
        frame.grid_columnconfigure(1, weight=0)
        frame.grid_columnconfigure(2, weight=0)
        frame.grid_columnconfigure(3, weight=0)

        lbl_account = tk.Label(frame, text=account,
                               fg="cyan", bg="#1E1E2E", font=("Arial", 12, "bold"), anchor="w")
        lbl_account.grid(row=0, column=0, sticky="w", padx=10)

        lbl_code = tk.Label(frame, text="------",
                            fg="white", bg="#1E1E2E", font=("Consolas", 18), width=8)
        lbl_code.grid(row=0, column=1, padx=10)

        lbl_timer = tk.Label(frame, text="30s",
                             fg="orange", bg="#1E1E2E", font=("Arial", 12), width=4)
        lbl_timer.grid(row=0, column=2, padx=10)

        del_btn = tk.Button(frame, text="❌",
                            command=lambda acc=account: self.show_delete_confirmation(acc),
                            bg="red", fg="white", font=("Arial", 10, "bold"), width=3)
        del_btn.grid(row=0, column=3, padx=5)

        self.labels[account] = (secret, lbl_code, lbl_timer)

    def update_totps(self):
        """Update all TOTP codes and countdown timers every second."""
        now = int(time.time())
        remaining = 30 - (now % 30)

        for account, (secret, lbl_code, lbl_timer) in list(self.labels.items()):
            if not lbl_code.winfo_exists() or not lbl_timer.winfo_exists():
                continue
            try:
                totp = pyotp.TOTP(secret)
                lbl_code.config(text=totp.now())
                lbl_timer.config(text=f"{remaining}s")
            except Exception:
                lbl_code.config(text="Invalid Key")
                lbl_timer.config(text="--")

        self.root.after(1000, self.update_totps)


# Main Entry Point
if __name__ == "__main__":
    generate_key()
    root = tk.Tk()
    app = TOTPApp(root)
    root.mainloop()
