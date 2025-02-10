# secureApk

# APK Vulnerability Scanner

## Features
This tool decompiles an APK using Apktool and scans the decompiled source code for various security vulnerabilities, including:

### Cryptographic Issues
- Detection of insecure cryptographic algorithms like ECB mode in AES.
- Weak random number generation.
- Presence of private keys in source code.

### Logging & Debugging Issues
- Debug logs that might expose sensitive information.
- Debugging enabled in the AndroidManifest.xml.

### Data Leakage & Hardcoded Secrets
- API keys and authentication tokens.
- Hardcoded HTTP URLs.
- Sensitive information like passwords and secrets in the code.

### Insecure Storage & Permissions
- Usage of external storage.
- Weak file permissions.
- SharedPreferences storing data insecurely.

### WebView & URL Handling Issues
- Insecure WebView settings (e.g., JavaScript enabled, file access allowed).
- Custom URL schemes that might be exploited.
- Implicit intents that may cause security issues.

### Broadcast & Intent Security Issues
- Insecure broadcast receivers.
- Improper usage of PendingIntents.

### Task & Activity Security Issues
- Task hijacking vulnerabilities.
- Insecure permission granting.
- Exported services that might be exploited.

### Network & SSL Issues
- Weak SSL/TLS protocols.
- Missing certificate validation checks.

### SQL Security Issues
- Insecure database usage.
- Potential SQL injection risks.

### Other Issues
- AllowBackup enabled.
- Use of weak random number functions.
- Exported services in AndroidManifest.xml.
- Potentially obfuscated code detection.

---

## Installation
### Prerequisites
Ensure you have the following installed on your system:
- Python 3
- Apktool
- Required Python packages (if any)

### Steps
1. Clone this repository:
   ```bash
   git clone https://github.com/your-repo/apk-vulnerability-scanner.git
   cd apk-vulnerability-scanner
   ```
2. Install dependencies (if any):
   ```bash
   pip install -r requirements.txt
   ```

---

## Usage
To analyze an APK for security vulnerabilities, use the following command:
```bash
python main.py <path-to-apk> <output-folder>
```
Example:
```bash
python main.py app.apk output/
```

This will decompile the APK using Apktool and scan the decompiled files for vulnerabilities.

---

## License
This project is open-source and provided under the MIT License.

