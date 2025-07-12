# payloadgen
PAYLOADGEN
# PayloadGen

**PayloadGen** is a modular payload generation tool for web vulnerability testing, designed to assist penetration testers, bug bounty hunters, and security researchers in crafting evasion-ready payloads for:

- ✅ XSS (Reflected, Stored, and DOM-based)
- ✅ SQL Injection (Error-based, Union-based, Blind)
- ✅ Command Injection (Linux & Windows)
- ✅ Includes WAF and filter evasion techniques

The tool supports both a **Command-Line Interface (CLI)** and an optional **GUI (Tkinter)** for ease of use.

---

## 🔧 Features

### 🔹 Vulnerability Payload Modules

- **XSS Generator**
  - Classic and bypass payloads using `<svg>`, `<img>`, `srcdoc`, event handlers, etc.
- **SQLi Generator**
  - Error-based, union-select, blind injection strings
  - Obfuscation: mixed casing, SQL comments (`/**/`)
- **Command Injection**
  - Compatible with Linux and Windows
  - Payloads using `;`, `|`, `&&`, backticks, etc.

---

### 🔹 Advanced Features

- **Encoding Options**
  - Base64
  - URL Encoding
  - Hex (`\x`)
  - Unicode (`\u`)
- **Obfuscation**
  - Space injection using `/**/`
  - Null byte `%00` injection
- **Output Options**
  - JSON formatted output
  - Copy first payload to clipboard
  - GUI with dropdowns and export button

---

## 🖥️ Usage

### 📦 CLI Version

#### Basic XSS Payloads
```bash
python3 payloadgen_cli.py --xss
python3 payloadgen_cli.py --sqli --encode=hex
python3 payloadgen_cli.py --cmd --obfuscate --copy
python3 payloadgen_cli.py --xss --json
python3 payloadgen_gui.py
payloadgen/
├── payloadgen_cli.py     # CLI version
├── payloadgen_gui.py     # GUI version (Tkinter)
├── README.md             # This file
├── requirements.txt      # Optional pip dependencies (pyperclip)
Python 3.7+

pyperclip (install via pip):

bash
Copy
Edit
pip install pyperclip
PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==
Decoded: <script>alert(1)</script>
'/**/UNION/**/SELECT/**/1,2,3-- 

