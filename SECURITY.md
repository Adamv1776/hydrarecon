# 🔐 HydraRecon Security Documentation

## Overview

HydraRecon is a powerful penetration testing and security assessment tool. Due to its nature, it includes capabilities that could be dangerous if misused. This document outlines security best practices for deploying, configuring, and using HydraRecon safely.

---

## ⚠️ Security Warnings

### This Tool is for Authorized Testing Only

HydraRecon should **ONLY** be used:
- On systems you own
- On systems you have explicit written authorization to test
- In isolated lab environments

Unauthorized use of this tool is **illegal** and may result in criminal prosecution.

---

## 🛡️ Security Best Practices

### 1. Configuration Security

#### SSL/TLS Verification
```yaml
# config.yaml - RECOMMENDED (default)
verify_ssl: true

# Only disable for isolated testing environments
# verify_ssl: false  # NOT RECOMMENDED
```

**Never disable SSL verification in production environments.** This makes your connections vulnerable to man-in-the-middle attacks.

#### Credential Storage
- **Never store plaintext passwords** in configuration files
- Use environment variables for sensitive data:
  ```bash
  export HYDRA_API_KEY="your-api-key-here"
  ```
- All credentials are automatically redacted in logs

### 2. Database Security

All database files (`*.db`) are:
- Automatically excluded from git via `.gitignore`
- Stored locally only
- Should be encrypted at rest on sensitive systems

**Recommendation:** Use full-disk encryption on systems running HydraRecon.

### 3. Log Security

HydraRecon implements automatic credential redaction in logs:
- Passwords are replaced with `[REDACTED]`
- API keys are masked
- Tokens are hidden
- Credit card numbers are partially masked

Example log output:
```
[+] SUCCESS: admin:[REDACTED]
[+] API call with token: [REDACTED]
```

### 4. Network Security

#### Running HydraRecon
- Always run on an **isolated network** or **VPN**
- Use a **dedicated testing machine** or VM
- **Never run on production networks** unless specifically authorized

#### Outbound Connections
- HydraRecon may connect to threat intelligence feeds
- Monitor outbound connections in sensitive environments
- Use firewall rules to restrict unnecessary network access

---

## 🔒 Security Features

### Secure Random Generation
HydraRecon uses `secrets` module (CSPRNG) for all security-sensitive random generation:
- Session tokens
- Encryption keys
- Unique identifiers

### Path Traversal Prevention
All file operations use sanitized paths:
```python
from core.security_utils import sanitize_path, sanitize_filename

# Safe file handling
safe_path = sanitize_path(user_input, base_directory)
safe_name = sanitize_filename(user_filename)
```

### Input Validation
Built-in validators for:
- IP addresses (IPv4/IPv6)
- Hostnames
- Port numbers
- URLs
- Command arguments

---

## 🚨 Known Security Considerations

### 1. Dangerous Features

Some features in HydraRecon are inherently dangerous by design:

| Feature | Risk | Mitigation |
|---------|------|------------|
| Payload Generator | Generates exploit code | Use only in authorized tests |
| C2 Framework | Command & control capabilities | Isolated environment only |
| Credential Spraying | Authentication testing | Authorized systems only |
| Social Engineering | Phishing simulations | Written authorization required |

### 2. Code Execution

The following modules can execute code:
- `payload_generator.py` - Generates and may compile payloads
- `c2_framework.py` - Executes agent commands
- `exploit_framework.py` - Runs exploit code

**Always review generated code before execution.**

### 3. Shell Commands

Some features execute shell commands. These are:
- Sanitized using `sanitize_command_arg()`
- Logged for audit purposes
- Executed with minimal privileges when possible

---

## 📋 Pre-Deployment Checklist

Before deploying HydraRecon publicly:

- [ ] **SSL verification enabled** (`verify_ssl: true`)
- [ ] **All `.db` files excluded** from version control
- [ ] **No hardcoded credentials** in source files
- [ ] **Debug logging disabled** in production
- [ ] **Firewall rules configured** to limit exposure
- [ ] **Access controls implemented** (authentication enabled)
- [ ] **Encryption enabled** for stored credentials
- [ ] **Audit logging active** for compliance
- [ ] **Terms of service** clearly stating authorized use only
- [ ] **Legal disclaimer** displayed on first run

---

## 🔑 Environment Variables

Recommended environment variables for sensitive configuration:

```bash
# API Keys
export HYDRA_SHODAN_API_KEY="your-shodan-key"
export HYDRA_VIRUSTOTAL_API_KEY="your-vt-key"
export HYDRA_CENSYS_API_KEY="your-censys-key"

# Database Encryption (if enabled)
export HYDRA_DB_ENCRYPTION_KEY="your-32-byte-key-here"

# Authentication Secret
export HYDRA_AUTH_SECRET="your-jwt-secret"
```

---

## 🛠️ Security Utilities

HydraRecon includes `core/security_utils.py` with secure helper functions:

### Secure Random Generation
```python
from core.security_utils import generate_secure_token, generate_secure_key

token = generate_secure_token(32)  # Cryptographically secure
key = generate_secure_key(32)       # For encryption
```

### Path Sanitization
```python
from core.security_utils import sanitize_path, sanitize_filename

# Prevent path traversal
safe_path = sanitize_path("../../../etc/passwd", "/app/uploads")
# Returns None (path escapes base directory)

safe_name = sanitize_filename("../malicious.exe")
# Returns "malicious.exe" (directory components removed)
```

### Credential Redaction
```python
from core.security_utils import redact_sensitive_data

log_message = "Login with password=secret123"
safe_message = redact_sensitive_data(log_message)
# Returns: "Login with password=[REDACTED]"
```

### Input Validation
```python
from core.security_utils import validate_ip, validate_port, validate_hostname

validate_ip("192.168.1.1")      # True
validate_ip("invalid")          # False
validate_port(443)              # True
validate_port(99999)            # False
validate_hostname("example.com") # True
```

---

## 📝 Reporting Security Issues

If you discover a security vulnerability in HydraRecon:

1. **Do NOT** open a public issue
2. Email security concerns privately
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

We take security seriously and will respond within 48 hours.

---

## 📄 License & Legal

HydraRecon is provided "as-is" without warranty. Users are solely responsible for:
- Obtaining proper authorization before testing
- Complying with all applicable laws
- Any damages resulting from use or misuse

**Use responsibly. Hack ethically.**

---

*Last Updated: 2024*
