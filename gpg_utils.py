# gnutomb/gpg_utils.py (v1.0.0)
"""Utilities for GnuPG interactions."""

import logging
import sys
from typing import Optional

# Attempt GnuPG import early
try:
    import gnupg
except ImportError:
    print("ERROR: python-gnupg library not found (`pip install python-gnupg`). GPG features disabled.", file=sys.stderr)
    gnupg = None # Define gnupg as None if import fails

# Import config AFTER it's loaded and validated
from config import settings
from mcp.model import ToolInputError # Use ToolInputError for consistent exceptions

logger = logging.getLogger("GPGUtils") # Get logger configured in server.py

GPG: Optional[gnupg.GPG] = None

# --- Initialization ---
def setup_gpg():
    """Initializes the GnuPG instance and verifies the service key."""
    global GPG
    if not gnupg: # Check if import failed
        logger.critical("python-gnupg library is not installed. Cannot initialize GPG.")
        raise RuntimeError("GPG library missing.")

    log_extra = {"gnupghome": settings.GNUPG_HOME, "gpgbinary": settings.GPG_BINARY}
    logger.info("Initializing GnuPG wrapper...", extra=log_extra)
    try:
        gpg_kwargs = {}
        if settings.GNUPG_HOME: gpg_kwargs['gnupghome'] = str(settings.GNUPG_HOME)
        if settings.GPG_BINARY: gpg_kwargs['gpgbinary'] = str(settings.GPG_BINARY)

        GPG = gnupg.GPG(**gpg_kwargs)
        GPG.encoding = 'utf-8'

        # Verify GPG is working
        version = GPG.version
        if not version: raise RuntimeError("gpg.version returned None.")
        logger.info(f"GnuPG Initialized. Version: {version}", extra=log_extra)

        # Verify service key exists (public for encrypt, private for decrypt)
        if not GPG.list_keys(secret=False, keys=[settings.SERVICE_GPG_KEYID]):
             logger.critical(f"Service GPG PUBLIC key not found in keyring.", extra=log_extra | {"keyid": settings.SERVICE_GPG_KEYID})
             raise RuntimeError(f"Service public key {settings.SERVICE_GPG_KEYID} not found.")
        if not GPG.list_keys(secret=True, keys=[settings.SERVICE_GPG_KEYID]):
             logger.critical(f"Service GPG PRIVATE key not found in keyring.", extra=log_extra | {"keyid": settings.SERVICE_GPG_KEYID})
             raise RuntimeError(f"Service private key {settings.SERVICE_GPG_KEYID} not found.")
        logger.info("Service GPG public and private keys verified in keyring.", extra=log_extra | {"keyid": settings.SERVICE_GPG_KEYID})

    except FileNotFoundError:
        logger.critical("GnuPG binary not found.", extra=log_extra, exc_info=True)
        raise RuntimeError("GnuPG binary not found.")
    except Exception as e:
        logger.critical("Failed to initialize GnuPG or verify service key.", extra=log_extra, exc_info=True)
        GPG = None # Ensure GPG is None if setup failed
        raise RuntimeError(f"GnuPG initialization failed: {e}") from e

def is_gpg_available() -> bool:
    """Checks if GPG instance was initialized successfully."""
    return GPG is not None

# --- Helper to check GPG result ---
def _check_gpg_result(operation: str, result: gnupg.Crypt):
    """Checks GPG result status and stderr, raises ToolInputError on failure."""
    # Use ToolInputError codes defined in server.py if possible, or keep generic
    from server import ErrorCode # Import ErrorCode from server

    status = getattr(result, 'status', f'{operation} failed')
    stderr = getattr(result, 'stderr', 'Unknown GPG error.')
    ok = getattr(result, 'ok', False)

    if not ok:
        log_extra = {"gpg_status": status, "gpg_stderr": stderr, "operation": operation}
        logger.error(f"GPG {operation} failed", extra=log_extra)
        if "bad passphrase" in stderr.lower(): raise ToolInputError(f"GPG {operation} failed: Service key passphrase issue.", code=ErrorCode.INTERNAL_ERROR) # Should not happen if setup correctly
        elif "no secret key" in stderr.lower(): raise ToolInputError(f"GPG {operation} failed: Service private key unavailable.", code=ErrorCode.INTERNAL_ERROR)
        elif "no public key" in stderr.lower(): raise ToolInputError(f"GPG {operation} failed: Service public key unavailable.", code=ErrorCode.INTERNAL_ERROR)
        elif "key expired" in stderr.lower(): raise ToolInputError(f"GPG {operation} failed: Service key expired.", code=ErrorCode.INTERNAL_ERROR)
        else: raise ToolInputError(f"GPG {operation} failed. Check server logs (Status: '{status}').", code=ErrorCode.INTERNAL_ERROR)
    # Check for empty data on encrypt/decrypt
    if operation in ["encrypt", "decrypt"] and not getattr(result, 'data', None):
        log_extra = {"gpg_status": status, "gpg_stderr": stderr, "operation": operation}
        logger.error(f"GPG {operation} ok but produced empty output data.", extra=log_extra)
        raise ToolInputError(f"GPG {operation} produced no output unexpectedly.", code=ErrorCode.INTERNAL_ERROR)

# --- Core GPG Operations ---
def encrypt_data(plaintext_bytes: bytes) -> bytes:
    """Encrypts data using the configured service GPG key."""
    if not GPG: raise ToolInputError("GPG Service unavailable.", code="INTERNAL_ERROR")
    log_extra = {"keyid": settings.SERVICE_GPG_KEYID}
    logger.debug("Encrypting data.", extra=log_extra)
    try:
        # Encrypt to the service key ID, non-armored binary output
        encrypted_data = GPG.encrypt(
            plaintext_bytes,
            recipients=[settings.SERVICE_GPG_KEYID],
            armor=False,
            always_trust=True # Service key should be implicitly trusted by itself
        )
        _check_gpg_result("encrypt", encrypted_data)
        logger.debug("Encryption successful.", extra=log_extra)
        return encrypted_data.data
    except Exception as e: # Catch unexpected errors from gpg call
        logger.error("Unexpected error during GPG encryption.", extra=log_extra, exc_info=True)
        # Map to ToolInputError if it wasn't already one from _check_gpg_result
        if isinstance(e, ToolInputError): raise
        raise ToolInputError("Internal GPG encryption error.", code="INTERNAL_ERROR") from e


def decrypt_data(ciphertext_bytes: bytes) -> bytes:
    """Decrypts data using the service's private GPG key."""
    if not GPG: raise ToolInputError("GPG Service unavailable.", code="INTERNAL_ERROR")
    log_extra = {"keyid": settings.SERVICE_GPG_KEYID} # Key used for decryption not specified, but implied
    logger.debug("Decrypting data.", extra=log_extra)
    try:
        # Decrypt using keys in keyring. Assumes service private key is available
        # and does NOT require a passphrase interactively (use agent or no passphrase).
        decrypted_data = GPG.decrypt(ciphertext_bytes) # No passphrase argument
        _check_gpg_result("decrypt", decrypted_data)
        logger.debug("Decryption successful.", extra=log_extra)
        return decrypted_data.data
    except Exception as e:
        logger.error("Unexpected error during GPG decryption.", extra=log_extra, exc_info=True)
        if isinstance(e, ToolInputError): raise
        raise ToolInputError("Internal GPG decryption error.", code="INTERNAL_ERROR") from e
