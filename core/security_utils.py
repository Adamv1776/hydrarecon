#!/usr/bin/env python3
"""
HydraRecon Security Utilities
Secure functions for cryptography, path handling, and data sanitization.
"""

import os
import re
import secrets
import hashlib
import hmac
from pathlib import Path
from typing import Optional, Any, Dict
from functools import wraps
import logging


# ==============================================================================
# SECURE RANDOM GENERATION
# ==============================================================================

def generate_secure_token(length: int = 32) -> str:
    """
    Generate a cryptographically secure random token.
    Uses secrets module (CSPRNG) instead of random module.
    
    Args:
        length: Length of the hex token (will be length/2 bytes)
    
    Returns:
        Secure random hex string
    """
    return secrets.token_hex(length // 2)


def generate_secure_id(prefix: str = "") -> str:
    """
    Generate a secure unique identifier.
    
    Args:
        prefix: Optional prefix for the ID
    
    Returns:
        Secure random ID string
    """
    random_part = secrets.token_hex(8)
    if prefix:
        return f"{prefix}_{random_part}"
    return random_part


def generate_secure_key(length: int = 32) -> bytes:
    """
    Generate cryptographically secure random bytes for encryption keys.
    
    Args:
        length: Number of bytes to generate
    
    Returns:
        Secure random bytes
    """
    return secrets.token_bytes(length)


# ==============================================================================
# PATH SANITIZATION (Prevent Path Traversal)
# ==============================================================================

def sanitize_filename(filename: str) -> str:
    """
    Sanitize a filename to prevent path traversal attacks.
    Removes directory traversal sequences and dangerous characters.
    
    Args:
        filename: The filename to sanitize
    
    Returns:
        Sanitized filename safe for file operations
    """
    if not filename:
        return "unnamed"
    
    # Remove any path components
    filename = os.path.basename(filename)
    
    # Remove null bytes
    filename = filename.replace('\x00', '')
    
    # Remove directory traversal patterns
    filename = filename.replace('..', '')
    filename = filename.replace('/', '')
    filename = filename.replace('\\', '')
    
    # Remove other dangerous characters
    dangerous_chars = ['<', '>', ':', '"', '|', '?', '*', '\n', '\r', '\t']
    for char in dangerous_chars:
        filename = filename.replace(char, '')
    
    # Ensure filename isn't empty after sanitization
    filename = filename.strip()
    if not filename:
        return "unnamed"
    
    # Limit length
    if len(filename) > 255:
        name, ext = os.path.splitext(filename)
        filename = name[:255 - len(ext)] + ext
    
    return filename


def sanitize_path(path: str, base_dir: str) -> Optional[Path]:
    """
    Sanitize a path and ensure it stays within the base directory.
    Prevents path traversal attacks.
    
    Args:
        path: The path to sanitize
        base_dir: The base directory that the path must stay within
    
    Returns:
        Safe Path object or None if path escapes base directory
    """
    try:
        # Resolve the base directory to absolute path
        base = Path(base_dir).resolve()
        
        # Join and resolve the target path
        target = (base / path).resolve()
        
        # Ensure target is within base directory
        if not str(target).startswith(str(base)):
            return None
        
        return target
    except (ValueError, OSError):
        return None


def is_safe_path(path: str, base_dir: str) -> bool:
    """
    Check if a path is safe (doesn't escape the base directory).
    
    Args:
        path: The path to check
        base_dir: The base directory that the path must stay within
    
    Returns:
        True if path is safe, False otherwise
    """
    return sanitize_path(path, base_dir) is not None


# ==============================================================================
# DATA SANITIZATION / REDACTION
# ==============================================================================

# Patterns for sensitive data that should be redacted
SENSITIVE_PATTERNS = [
    (r'(password["\']?\s*[:=]\s*["\']?)([^"\']+)(["\']?)', r'\1[REDACTED]\3'),
    (r'(api[_-]?key["\']?\s*[:=]\s*["\']?)([^"\']+)(["\']?)', r'\1[REDACTED]\3'),
    (r'(secret["\']?\s*[:=]\s*["\']?)([^"\']+)(["\']?)', r'\1[REDACTED]\3'),
    (r'(token["\']?\s*[:=]\s*["\']?)([^"\']+)(["\']?)', r'\1[REDACTED]\3'),
    (r'(auth["\']?\s*[:=]\s*["\']?)([^"\']+)(["\']?)', r'\1[REDACTED]\3'),
    (r'(bearer\s+)([a-zA-Z0-9._-]+)', r'\1[REDACTED]'),
    (r'(basic\s+)([a-zA-Z0-9+/=]+)', r'\1[REDACTED]'),
    # Credit card patterns
    (r'\b(\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?)\d{4}\b', r'\1****'),
    # SSN pattern
    (r'\b(\d{3}[-\s]?\d{2}[-\s]?)\d{4}\b', r'\1****'),
]


def redact_sensitive_data(data: str) -> str:
    """
    Redact sensitive data from a string (passwords, API keys, tokens, etc.).
    
    Args:
        data: The string potentially containing sensitive data
    
    Returns:
        String with sensitive data redacted
    """
    result = data
    for pattern, replacement in SENSITIVE_PATTERNS:
        result = re.sub(pattern, replacement, result, flags=re.IGNORECASE)
    return result


def redact_credentials(username: str, password: str) -> tuple:
    """
    Return credentials with password redacted for logging.
    
    Args:
        username: The username
        password: The password to redact
    
    Returns:
        Tuple of (username, redacted_password)
    """
    return (username, '*' * min(len(password), 8) if password else '')


def safe_log(logger: logging.Logger, level: str, message: str, **kwargs):
    """
    Log a message with automatic sensitive data redaction.
    
    Args:
        logger: The logger instance
        level: Log level (debug, info, warning, error, critical)
        message: The message to log
        **kwargs: Additional structured data to log
    """
    # Redact the message
    safe_message = redact_sensitive_data(message)
    
    # Redact any kwargs
    safe_kwargs = {}
    for key, value in kwargs.items():
        if isinstance(value, str):
            safe_kwargs[key] = redact_sensitive_data(value)
        else:
            safe_kwargs[key] = value
    
    # Build final message
    if safe_kwargs:
        extra_info = ' | '.join(f'{k}={v}' for k, v in safe_kwargs.items())
        safe_message = f"{safe_message} | {extra_info}"
    
    getattr(logger, level.lower())(safe_message)


# ==============================================================================
# INPUT VALIDATION
# ==============================================================================

def validate_ip(ip: str) -> bool:
    """
    Validate an IP address (IPv4 or IPv6).
    
    Args:
        ip: The IP address to validate
    
    Returns:
        True if valid, False otherwise
    """
    import ipaddress
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def validate_port(port: int) -> bool:
    """
    Validate a port number.
    
    Args:
        port: The port number to validate
    
    Returns:
        True if valid (1-65535), False otherwise
    """
    return isinstance(port, int) and 1 <= port <= 65535


def validate_hostname(hostname: str) -> bool:
    """
    Validate a hostname.
    
    Args:
        hostname: The hostname to validate
    
    Returns:
        True if valid, False otherwise
    """
    if not hostname or len(hostname) > 255:
        return False
    
    # Remove trailing dot if present
    if hostname.endswith('.'):
        hostname = hostname[:-1]
    
    # Check each label
    allowed = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$')
    labels = hostname.split('.')
    
    return all(allowed.match(label) for label in labels)


def validate_url(url: str) -> bool:
    """
    Validate a URL.
    
    Args:
        url: The URL to validate
    
    Returns:
        True if valid, False otherwise
    """
    from urllib.parse import urlparse
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except Exception:
        return False


def sanitize_command_arg(arg: str) -> str:
    """
    Sanitize a command line argument to prevent injection.
    Removes shell metacharacters.
    
    Args:
        arg: The argument to sanitize
    
    Returns:
        Sanitized argument
    """
    # Remove shell metacharacters
    dangerous = ['|', ';', '&', '$', '`', '(', ')', '{', '}', 
                 '[', ']', '<', '>', '\n', '\r', '\x00']
    result = arg
    for char in dangerous:
        result = result.replace(char, '')
    return result


# ==============================================================================
# SECURE COMPARISON
# ==============================================================================

def secure_compare(a: str, b: str) -> bool:
    """
    Compare two strings in constant time to prevent timing attacks.
    
    Args:
        a: First string
        b: Second string
    
    Returns:
        True if strings are equal, False otherwise
    """
    return hmac.compare_digest(a.encode(), b.encode())


def hash_password(password: str, salt: Optional[bytes] = None) -> tuple:
    """
    Hash a password securely using PBKDF2.
    
    Args:
        password: The password to hash
        salt: Optional salt (will be generated if not provided)
    
    Returns:
        Tuple of (hash, salt)
    """
    if salt is None:
        salt = secrets.token_bytes(32)
    
    hash_bytes = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode(),
        salt,
        iterations=100000
    )
    
    return (hash_bytes.hex(), salt.hex())


def verify_password(password: str, hash_hex: str, salt_hex: str) -> bool:
    """
    Verify a password against a stored hash.
    
    Args:
        password: The password to verify
        hash_hex: The stored hash in hex
        salt_hex: The stored salt in hex
    
    Returns:
        True if password matches, False otherwise
    """
    salt = bytes.fromhex(salt_hex)
    computed_hash = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode(),
        salt,
        iterations=100000
    )
    
    return secure_compare(computed_hash.hex(), hash_hex)


# ==============================================================================
# DECORATOR FOR SECURITY LOGGING
# ==============================================================================

def audit_log(action: str):
    """
    Decorator to log security-sensitive function calls.
    
    Args:
        action: Description of the action being performed
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            logger = logging.getLogger("SecurityAudit")
            
            # Log the action (with redacted args)
            safe_args = [redact_sensitive_data(str(a)) for a in args]
            safe_kwargs = {k: redact_sensitive_data(str(v)) for k, v in kwargs.items()}
            
            logger.info(f"AUDIT: {action} | func={func.__name__} | args={safe_args[:3]} | kwargs={list(safe_kwargs.keys())}")
            
            try:
                result = func(*args, **kwargs)
                logger.info(f"AUDIT: {action} completed successfully")
                return result
            except Exception as e:
                logger.error(f"AUDIT: {action} failed | error={type(e).__name__}")
                raise
        
        return wrapper
    return decorator


# ==============================================================================
# SECURITY WARNINGS
# ==============================================================================

SECURITY_WARNINGS_SHOWN = set()


def security_warning(feature: str, message: str, show_once: bool = True):
    """
    Display a security warning to the user.
    
    Args:
        feature: The feature that has security implications
        message: The warning message
        show_once: Only show this warning once per session
    """
    if show_once and feature in SECURITY_WARNINGS_SHOWN:
        return
    
    SECURITY_WARNINGS_SHOWN.add(feature)
    
    logger = logging.getLogger("SecurityWarning")
    logger.warning(f"⚠️  SECURITY WARNING [{feature}]: {message}")


def dangerous_feature_check(feature_name: str):
    """
    Check if a dangerous feature should be allowed.
    Shows warning and requires explicit consent for dangerous operations.
    
    Args:
        feature_name: Name of the dangerous feature
    
    Returns:
        True (in production, this would require user confirmation)
    """
    warnings = {
        "shell_execution": "Shell command execution can be dangerous. Ensure commands are from trusted sources.",
        "code_execution": "Arbitrary code execution is enabled. This feature should only be used in isolated environments.",
        "ssl_disabled": "SSL verification is disabled. This makes connections vulnerable to MITM attacks.",
        "file_upload": "File upload functionality is active. Ensure proper validation is in place.",
        "credential_storage": "Credentials will be stored. Ensure encryption is enabled.",
    }
    
    if feature_name in warnings:
        security_warning(feature_name, warnings[feature_name])
    
    return True
