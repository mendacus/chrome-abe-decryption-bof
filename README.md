# chrome-abe-decryption-bof

_A Beacon Object File for decrypting Chrome App-Bound Encryption masterkeys in-memory via Cobalt Strike_

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)  

---

## ⚡️ Introduction & Objective

This is my **first public security project**, created as a proof-of-concept. It packages the work of [xaitax’s Chrome App-Bound Encryption Decryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption/tree/main) into:

1. **A BOF** (`bof/`) for in-memory decryption via Cobalt Strike, preserving OPSEC  
2. **A standalone decryptor EXE** (`decryptor/`) for on-disk key & blob processing  

> **Caveats**  
> - **Profiles not supported** — the BOF always looks in the hard-coded path for `Local State`. You can change the lookup path in `bof/chrome_decrypt.cpp` for your profile folder.  
> - **Chrome-only & Cobalt Strike-only** for now; future versions may target other Chromium browsers (e.g., Edge, Brave).

---

## 📦 Repository Layout

```text
chrome-abe-decryption-bof/
├── bof/              # BOF Visual Studio solution & project  
│   ├── ChromeABEDecryption-BOF.sln  
│   ├── bof.cpp  
│   └── … other project files
├── decryptor/        # Standalone decryptor solution & code    
│   ├── decryptor.cpp  
│   └── sqlite3.c  
├── docs/             # Setup guides, architecture & extended docs  
├── .gitignore        # Ignore build outputs & VS user files  
├── LICENSE           # MIT License  
└── README.md         # ← you are here  
```

---

## 🛠️ Prerequisites

- **Windows** with Visual Studio 2022+ (Desktop C++ workload)  
- **cl.exe**, **bcrypt.lib**, **crypt32.lib** (for decryptor)  
- **Cobalt Strike** (for BOF usage)

---

## 🏗️ Compilation

### 1. BOF

1. Follow the BOF template setup in `docs/setup-bof-vs.md` (based on [chryzsh’s guide](https://github.com/chryzsh/awesome-bof/blob/main/how-to/setup-visual-studio-bof.md)).  
2. Open `bof/ChromeABEDecryption-BOF.sln` in Visual Studio.  
3. Select **x64** and **Release**, then **Build**.  
4. Locate the generated `.o` in your VS source output folder (e.g. `C:\Users\<youruser>\source\repos\x64\Release`).

### 2. Decryptor

In a Developer PowerShell or CMD:

```powershell
cd decryptor
cl /EHsc /std:c++17 decryptor.cpp sqlite3.c /I. /link bcrypt.lib crypt32.lib
```

This produces `decryptor.exe` in the same folder.

---

## 🚀 Usage

### BOF (in-memory on target)

1. **Spawn** a Beacon session in Cobalt Strike.  
2. **Inject** into the **parent** `chrome.exe` process.  
3. Run:
   ```
   inline-execute bof.x64.o
   ```
4. The BOF will dump the **masterkey** to your Beacon console. Save it safely.

> **Note:** Chrome’s parent vs. child processes—always target the original chrome.exe.

### Decryptor (on-attacker-disk / offline)

1. **Kill** Chrome on victim machine to safely copy the `Cookies`, `Login Data`, and `Web Data` files.  
2. Run:
   ```powershell
   decryptor.exe --key <hex32-masterkey> `
     --cookies "C:\Path\To\Cookies" `
     --logins  "C:\Path\To\Login Data" `
     --webdata "C:\Path\To\Web Data"
   ```
3. The tool outputs CSVs for logins, cookies, and web data in the current folder.

---

## 🛣️ Next Steps & Future Development

- **Profile support**: Dynamically enumerate Chrome profiles instead of hard-coded paths.  
- **Multi-browser**: Extend BOF & decryptor to Edge, Brave, and other Chromium-based browsers.  
- **Runbooks & automation**: Build helper scripts and docs to streamline OPSEC-friendly workflows.

---

## 🤝 Contributing

Contributions are welcome! Let me know if you:

- Have an issue  
- Have pull requests  
---

## 📄 License

This project is licensed under the **MIT License**. See [LICENSE](LICENSE) for full text.
