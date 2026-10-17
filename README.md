# 🔐 Wajeeha Crypt

**Wajeeha Crypt** is a simple desktop app that encrypts and decrypts **individual files and folders** with a master password.
<img width="535" height="759" alt="image" src="https://github.com/user-attachments/assets/edead384-af3b-421f-88b7-c4b98bf2a7b8" />

It is inspired by [VeraCrypt](https://github.com/veracrypt/veracrypt), but where VeraCrypt encrypts whole drives and volumes, Wajeeha Crypt works at the **file level**: pick files or a folder, enter a password, and click **Encrypt**.

> ⚠️ **Disclaimer:** Wajeeha Crypt is an independent project. It is **not** affiliated with VeraCrypt or IDRIX, and it has **not** been independently security-audited. For highly sensitive data, use a well-established, audited tool.

---

## ✨ Features

- **File and folder encryption**: encrypt single files, many files, or whole folders (subfolders included).
- **Drag & drop**: drop files or folders straight into the Files box.
- **Master password**: one password protects everything you encrypt in a session.
- **Hides file type and contents**: works with text, images, audio, video, documents, or anything else.
  - The original name and extension are stored *inside* the encrypted data.
  - Encrypted files get a random name and have no recognizable header.
- **Tamper detection**: a wrong password or a modified or corrupted file is detected and refused.
- **Handles large files**: data is processed in 1 MB chunks, so big videos don't fill your RAM.
- **Safe restore**: decrypting never overwrites an existing file.
- **Responsive UI**: work runs in the background with a live progress bar and status log.
- **Cross-platform**: pure Python and Tkinter, so it runs on Windows, macOS and Linux.

---

## 🖼️ Interface

| Element | Purpose |
|---|---|
| **Browse File/Folder** | Pick files or a folder to process |
| **Files** | List of items queued (also a drag & drop target) |
| **Master Password / Confirm Password** | Your encryption password |
| **ENCRYPT / DECRYPT** | Start the operation |
| **Status** | Log of results and a progress bar |

---

## 🔒 How it works

| Component | Choice |
|---|---|
| Cipher | AES-256-GCM (authenticated encryption) |
| Key derivation | scrypt (N=2¹⁶, r=8, p=1), memory-hard to slow down password guessing |
| Salt | 32 random bytes, **unique per file**, so every file has its own key |
| Metadata | Original file name stored in a fixed-size encrypted block (hides name length) |
| Chunking | 1 MB chunks; each chunk is authenticated and the final chunk is flagged, so truncation is detected |
| Output name | Random hex name plus `.wcrypt` (the extension is configurable in the code) |

**Encrypted file layout**

```
[ 32-byte salt ][ encrypted metadata block ][ encrypted chunk 1 ][ encrypted chunk 2 ] ...
```

There is no magic number or plaintext header, so an encrypted file looks like random data.

---

## 📦 Requirements

- Python **3.10+**
- [`cryptography`](https://pypi.org/project/cryptography/)
- [`tkinterdnd2`](https://pypi.org/project/tkinterdnd2/) *(optional, enables drag & drop)*
- Tkinter (included with Python on Windows and macOS; on some Linux distros install `python3-tk`)

---

## 🚀 Getting started

### 1. Clone the repository

```bash
git clone https://github.com/<your-username>/wajeeha-crypt.git
cd wajeeha-crypt
```

### 2. Install dependencies

```bash
pip install cryptography tkinterdnd2
```

### 3. Run

```bash
python wajeeha_crypt.py
```

---

## 🧭 Usage

### Encrypt

1. Click **Browse** and choose files or a folder, or drag and drop them into the **Files** box.
2. Enter a **Master Password** (at least 8 characters) and type it again in **Confirm Password**.
3. *(Optional)* Tick **Delete original files after encrypting**.
4. Click **ENCRYPT**.

Each file is replaced by a randomly named `.wcrypt` file in the same folder.

### Decrypt

1. Add the `.wcrypt` files, or a folder containing them.
2. Enter the **Master Password** you used to encrypt.
3. Click **DECRYPT**.

The original files are restored with their original names and extensions, next to the encrypted files.

> When you decrypt a **folder**, only files ending in `.wcrypt` are picked up. If you renamed an encrypted file, add it to the list individually.

---

## 🛠️ Build a standalone executable

Use [PyInstaller](https://pyinstaller.org/) to create a single-file app that doesn't need Python installed:

```bash
pip install pyinstaller
pyinstaller --onefile --windowed --collect-all tkinterdnd2 --name "Wajeeha Crypt" wajeeha_crypt.py
```

The result is in the `dist/` folder. Build on the operating system you are targeting, since PyInstaller does not cross-compile.

> Some antivirus tools flag unsigned PyInstaller executables as suspicious. This is a common false positive.

---

## ⚠️ Important notes

- **No password recovery.** If you forget your master password, your files **cannot** be recovered. There is no backdoor.
- **Back up first.** Test on copies of your files before encrypting anything important.
- **"Delete original" is not a secure wipe.** On SSDs and some file systems, deleted data may still be recoverable. Keep this option off until you've confirmed that decryption works.
- **Metadata still visible.** The file name and extension are hidden, but the approximate file size, the folder structure, and timestamps remain visible to the operating system.
- **Use a strong password.** A long passphrase (12+ characters, ideally several random words) is much stronger than a short complex one.
- **Not audited.** See the disclaimer above.


---

## 🤝 Contributing

Issues and pull requests are welcome. Please open an issue first to discuss major changes. For anything security-related, describe the concern clearly and include the steps to reproduce it.

---

## 📄 License

[MIT](https://choosealicense.com/licenses/mit/)
