"""
Wajeeha Crypt - simple file & folder encryption with a master password.

Security design
---------------
* Key derivation : scrypt (memory-hard, slows down password guessing)
* Encryption     : AES-256-GCM (encrypts AND detects tampering / wrong password)
* Every file gets its own random salt -> its own unique key
* Original file name + extension are stored INSIDE the encrypted data
* Encrypted file has NO header/magic bytes: it looks like random data
* Encrypted file gets a random name, so name/extension reveal nothing
* Works on any file type: text, image, audio, video, anything
"""

import json
import os
import queue
import secrets
import struct
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

# Optional drag & drop support (pip install tkinterdnd2)
try:
    from tkinterdnd2 import DND_FILES, TkinterDnD
    HAS_DND = True
except Exception:
    HAS_DND = False

APP_TITLE = "WAJEEHA CRYPT"
ENC_EXT = ".wcrypt"          # you may change this to anything you like
SALT_SIZE = 32
CHUNK = 1024 * 1024          # 1 MB chunks (big files are never loaded fully into RAM)
META_SIZE = 4096             # fixed-size metadata block (hides name length)
TAG = 16
SCRYPT_N = 2 ** 16
MIN_PASSWORD = 8


# --------------------------------------------------------------------------
# Crypto core
# --------------------------------------------------------------------------
def derive_key(password: str, salt: bytes) -> bytes:
    kdf = Scrypt(salt=salt, length=32, n=SCRYPT_N, r=8, p=1)
    return kdf.derive(password.encode("utf-8"))


def nonce_for(counter: int) -> bytes:
    # Safe because every file has its own unique key (random salt)
    return counter.to_bytes(12, "big")


def encrypt_file(src, dst, password, progress=lambda f: None):
    salt = secrets.token_bytes(SALT_SIZE)
    aes = AESGCM(derive_key(password, salt))

    meta = json.dumps({"name": os.path.basename(src)}).encode("utf-8")
    if len(meta) > META_SIZE - 2:
        raise ValueError("File name too long")
    meta_block = struct.pack(">H", len(meta)) + meta
    meta_block += b"\x00" * (META_SIZE - len(meta_block))

    total = max(os.path.getsize(src), 1)
    done = 0
    tmp = dst + ".part"
    try:
        with open(src, "rb") as fin, open(tmp, "wb") as fout:
            fout.write(salt)
            fout.write(aes.encrypt(nonce_for(0), meta_block, b"M"))
            counter = 1
            cur = fin.read(CHUNK)
            while True:
                nxt = fin.read(CHUNK)
                final = not nxt
                fout.write(aes.encrypt(nonce_for(counter), cur,
                                       b"\x01" if final else b"\x00"))
                counter += 1
                done += len(cur)
                progress(min(done / total, 1.0))
                if final:
                    break
                cur = nxt
        os.replace(tmp, dst)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)


def decrypt_file(src, out_dir, password, progress=lambda f: None):
    """Returns the path of the restored file."""
    total = max(os.path.getsize(src), 1)
    done = 0
    tmp = None
    try:
        with open(src, "rb") as fin:
            salt = fin.read(SALT_SIZE)
            meta_ct = fin.read(META_SIZE + TAG)
            if len(salt) < SALT_SIZE or len(meta_ct) < META_SIZE + TAG:
                raise ValueError("Not a valid encrypted file")
            aes = AESGCM(derive_key(password, salt))
            try:
                meta_block = aes.decrypt(nonce_for(0), meta_ct, b"M")
            except InvalidTag:
                raise ValueError("Wrong password or not an encrypted file")
            n = struct.unpack(">H", meta_block[:2])[0]
            name = json.loads(meta_block[2:2 + n].decode("utf-8"))["name"]
            name = os.path.basename(name) or "restored_file"

            # Never overwrite an existing file
            dst = os.path.join(out_dir, name)
            base, ext = os.path.splitext(dst)
            i = 1
            while os.path.exists(dst):
                dst = f"{base} (restored {i}){ext}"
                i += 1

            tmp = dst + ".part"
            with open(tmp, "wb") as fout:
                counter = 1
                cur = fin.read(CHUNK + TAG)
                while True:
                    nxt = fin.read(CHUNK + TAG)
                    final = not nxt
                    try:
                        plain = aes.decrypt(nonce_for(counter), cur,
                                            b"\x01" if final else b"\x00")
                    except InvalidTag:
                        raise ValueError("File is corrupted or was tampered with")
                    fout.write(plain)
                    counter += 1
                    done += len(cur)
                    progress(min(done / total, 1.0))
                    if final:
                        break
                    cur = nxt
        os.replace(tmp, dst)
        tmp = None
        return dst
    finally:
        if tmp and os.path.exists(tmp):
            os.remove(tmp)


def random_name(folder):
    while True:
        p = os.path.join(folder, secrets.token_hex(12) + ENC_EXT)
        if not os.path.exists(p):
            return p


def collect_files(paths, only_encrypted):
    """Expand folders into a list of files."""
    result = []
    for p in paths:
        if os.path.isdir(p):
            for root, _, files in os.walk(p):
                for f in files:
                    result.append(os.path.join(root, f))
        elif os.path.isfile(p):
            result.append(p)
    out = []
    for f in result:
        is_enc = f.lower().endswith(ENC_EXT)
        if only_encrypted and is_enc and not f.endswith(".part"):
            out.append(f)
        elif not only_encrypted and not is_enc and not f.endswith(".part"):
            out.append(f)
    return out


# --------------------------------------------------------------------------
# GUI
# --------------------------------------------------------------------------
BG = "#f4f6fa"
ACCENT = "#2b5fd9"


class App:
    def __init__(self, root):
        self.root = root
        self.q = queue.Queue()
        self.busy = False

        root.title("Wajeeha Crypt")
        root.geometry("520x720")
        root.minsize(480, 680)
        root.configure(bg=BG)

        style = ttk.Style()
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure("TFrame", background=BG)
        style.configure("TLabel", background=BG, font=("Segoe UI", 10))
        style.configure("TCheckbutton", background=BG, font=("Segoe UI", 9))
        style.configure("Big.TButton", font=("Segoe UI", 11, "bold"), padding=8)
        style.configure("Green.Horizontal.TProgressbar", background="#4caf50")

        # ---- Header
        header = tk.Label(root, text=APP_TITLE, bg=ACCENT, fg="white",
                          font=("Segoe UI", 16, "bold"), pady=12)
        header.pack(fill="x")

        body = ttk.Frame(root, padding=16)
        body.pack(fill="both", expand=True)
        body.columnconfigure(1, weight=1)

        # ---- Browse row
        ttk.Label(body, text="Browse File/Folder").grid(row=0, column=0, sticky="w", pady=6)
        self.path_var = tk.StringVar()
        ttk.Entry(body, textvariable=self.path_var).grid(row=0, column=1, sticky="ew", padx=8)
        self.browse_btn = ttk.Button(body, text="Browse", command=self.browse_menu)
        self.browse_btn.grid(row=0, column=2)
        self.browse_menu_w = tk.Menu(root, tearoff=0)
        self.browse_menu_w.add_command(label="Select files...", command=self.add_files)
        self.browse_menu_w.add_command(label="Select folder...", command=self.add_folder)

        # ---- Files list
        ttk.Label(body, text="Files").grid(row=1, column=0, sticky="nw", pady=6)
        lf = ttk.Frame(body)
        lf.grid(row=1, column=1, columnspan=2, sticky="nsew", padx=(8, 0), pady=6)
        body.rowconfigure(1, weight=1)
        self.listbox = tk.Listbox(lf, height=8, selectmode="extended",
                                  relief="solid", bd=1, font=("Segoe UI", 9))
        sb = ttk.Scrollbar(lf, command=self.listbox.yview)
        self.listbox.config(yscrollcommand=sb.set)
        self.listbox.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        self.listbox.bind("<Delete>", lambda e: self.remove_selected())

        hint = "Drag && drop files/folders here" if HAS_DND else \
            "(Install tkinterdnd2 to enable drag && drop)"
        hint = hint.replace("&&", "&")
        row = ttk.Frame(body)
        row.grid(row=2, column=1, columnspan=2, sticky="ew", padx=(8, 0))
        ttk.Label(row, text=hint, foreground="#666").pack(side="left")
        ttk.Button(row, text="Clear", width=7, command=self.clear_list).pack(side="right")
        ttk.Button(row, text="Remove", width=8, command=self.remove_selected).pack(side="right", padx=4)

        if HAS_DND:
            self.listbox.drop_target_register(DND_FILES)
            self.listbox.dnd_bind("<<Drop>>", self.on_drop)

        # ---- Passwords
        ttk.Label(body, text="Master Password").grid(row=3, column=0, sticky="w", pady=(16, 6))
        self.pw1 = ttk.Entry(body, show="*")
        self.pw1.grid(row=3, column=1, columnspan=2, sticky="ew", padx=(8, 0), pady=(16, 6))
        ttk.Label(body, text="Confirm Password").grid(row=4, column=0, sticky="w", pady=6)
        self.pw2 = ttk.Entry(body, show="*")
        self.pw2.grid(row=4, column=1, columnspan=2, sticky="ew", padx=(8, 0), pady=6)

        opts = ttk.Frame(body)
        opts.grid(row=5, column=1, columnspan=2, sticky="w", padx=(8, 0))
        self.show_var = tk.BooleanVar()
        ttk.Checkbutton(opts, text="Show password", variable=self.show_var,
                        command=self.toggle_pw).pack(anchor="w")
        self.del_var = tk.BooleanVar()
        ttk.Checkbutton(opts, text="Delete original files after encrypting",
                        variable=self.del_var).pack(anchor="w")

        # ---- Buttons
        bf = ttk.Frame(body)
        bf.grid(row=6, column=0, columnspan=3, pady=14)
        self.enc_btn = ttk.Button(bf, text="ENCRYPT", style="Big.TButton", width=14,
                                  command=lambda: self.start("encrypt"))
        self.enc_btn.pack(side="left", padx=10)
        self.dec_btn = ttk.Button(bf, text="DECRYPT", style="Big.TButton", width=14,
                                  command=lambda: self.start("decrypt"))
        self.dec_btn.pack(side="left", padx=10)

        # ---- Status
        ttk.Label(body, text="Status").grid(row=7, column=0, sticky="w")
        sf = ttk.Frame(body)
        sf.grid(row=8, column=0, columnspan=3, sticky="nsew")
        body.rowconfigure(8, weight=1)
        self.status = tk.Text(sf, height=8, state="disabled", relief="solid", bd=1,
                              font=("Consolas", 9), wrap="word")
        ssb = ttk.Scrollbar(sf, command=self.status.yview)
        self.status.config(yscrollcommand=ssb.set)
        self.status.pack(side="left", fill="both", expand=True)
        ssb.pack(side="right", fill="y")
        self.progress = ttk.Progressbar(body, style="Green.Horizontal.TProgressbar",
                                        maximum=100)
        self.progress.grid(row=9, column=0, columnspan=3, sticky="ew", pady=(4, 0))

        self.log("Ready. Add files or folders, enter your master password.")
        self.log("IMPORTANT: if you forget the password, files CANNOT be recovered.")
        self.root.after(100, self.poll)

    # ---- helpers
    def toggle_pw(self):
        ch = "" if self.show_var.get() else "*"
        self.pw1.config(show=ch)
        self.pw2.config(show=ch)

    def log(self, msg):
        self.status.config(state="normal")
        self.status.insert("end", msg + "\n")
        self.status.see("end")
        self.status.config(state="disabled")

    def browse_menu(self):
        self.browse_menu_w.tk_popup(self.browse_btn.winfo_rootx(),
                                    self.browse_btn.winfo_rooty() + self.browse_btn.winfo_height())

    def add_paths(self, paths):
        existing = set(self.listbox.get(0, "end"))
        for p in paths:
            p = os.path.normpath(p)
            if os.path.exists(p) and p not in existing:
                self.listbox.insert("end", p)
                existing.add(p)
                self.path_var.set(p)

    def add_files(self):
        self.add_paths(filedialog.askopenfilenames(title="Select files"))

    def add_folder(self):
        d = filedialog.askdirectory(title="Select folder")
        if d:
            self.add_paths([d])

    def on_drop(self, event):
        self.add_paths(self.root.tk.splitlist(event.data))

    def remove_selected(self):
        for i in reversed(self.listbox.curselection()):
            self.listbox.delete(i)

    def clear_list(self):
        self.listbox.delete(0, "end")
        self.path_var.set("")

    def set_busy(self, busy):
        self.busy = busy
        st = "disabled" if busy else "normal"
        self.enc_btn.config(state=st)
        self.dec_btn.config(state=st)

    # ---- actions
    def start(self, mode):
        if self.busy:
            return
        paths = list(self.listbox.get(0, "end"))
        if not paths:
            messagebox.showwarning("Wajeeha Crypt", "Please add files or folders first.")
            return
        pw = self.pw1.get()
        if len(pw) < MIN_PASSWORD:
            messagebox.showwarning("Wajeeha Crypt",
                                   f"Master password must be at least {MIN_PASSWORD} characters.")
            return
        if mode == "encrypt":
            if pw != self.pw2.get():
                messagebox.showerror("Wajeeha Crypt", "Passwords do not match.")
                return
            if self.del_var.get() and not messagebox.askyesno(
                    "Confirm", "Original files will be DELETED after encryption.\n"
                               "If you forget the password they are gone forever.\nContinue?"):
                return
        self.progress["value"] = 0
        self.set_busy(True)
        threading.Thread(target=self.worker, args=(mode, paths, pw, self.del_var.get()),
                         daemon=True).start()

    def worker(self, mode, paths, pw, delete_orig):
        q = self.q
        files = collect_files(paths, only_encrypted=(mode == "decrypt"))
        if not files:
            q.put(("log", "No suitable files found."))
            q.put(("done", None))
            return
        q.put(("log", f"--- {mode.upper()} started: {len(files)} file(s) ---"))
        ok = fail = 0
        for i, f in enumerate(files):
            def prog(frac, i=i):
                q.put(("prog", (i + frac) / len(files) * 100))
            try:
                folder = os.path.dirname(f)
                if mode == "encrypt":
                    dst = random_name(folder)
                    encrypt_file(f, dst, pw, prog)
                    if delete_orig:
                        os.remove(f)
                    q.put(("log", f"[OK] Encrypted: {os.path.basename(f)}"))
                else:
                    out = decrypt_file(f, folder, pw, prog)
                    q.put(("log", f"[OK] Restored: {os.path.basename(out)}"))
                ok += 1
            except Exception as e:
                fail += 1
                q.put(("log", f"[FAILED] {os.path.basename(f)}: {e}"))
        q.put(("prog", 100))
        q.put(("log", f"--- Finished: {ok} succeeded, {fail} failed ---"))
        q.put(("done", None))

    def poll(self):
        try:
            while True:
                kind, val = self.q.get_nowait()
                if kind == "log":
                    self.log(val)
                elif kind == "prog":
                    self.progress["value"] = val
                elif kind == "done":
                    self.set_busy(False)
        except queue.Empty:
            pass
        self.root.after(100, self.poll)


def main():
    root = TkinterDnD.Tk() if HAS_DND else tk.Tk()
    App(root)
    root.mainloop()


if __name__ == "__main__":
    main()
