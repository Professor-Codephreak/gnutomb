# gnutomb/config.py (v1.0.0)
"""Loads and validates configuration settings for the GnuTomb MCP Service from environment variables using Pydantic."""

import os
import json
import logging
import sys
import re
from pathlib import Path
from typing import Optional, List, Dict, Any
from pydantic import Field, validator, ValidationError
from pydantic_settings import BaseSettings

# Use standard logging temporarily during config parsing before full setup
logging.basicConfig(level="INFO")
config_logger = logging.getLogger("ConfigLoader")

# --- Helper Functions ---
def parse_bool(env_var: str, default: bool = False) -> bool:
    val_str = os.environ.get(env_var, "").lower()
    if val_str in ['true', '1', 'yes', 'on']: return True
    if val_str in ['false', '0', 'no', 'off']: return False
    return default

def parse_int(env_var: str, default: int, positive_only: bool = False, allow_zero: bool = False) -> int:
    val_str = os.environ.get(env_var)
    if val_str is None: return default
    try:
        val = int(val_str); min_val = 0 if allow_zero else 1
        if positive_only and val < min_val: raise ValueError(f"Must be >= {min_val}")
        return val
    except ValueError as e: config_logger.warning(f"Invalid integer for {env_var}: {e}. Using default {default}."); return default

def resolve_path(env_var: str, default: Optional[str] = None, check_is_dir: bool = False, check_is_file: bool = False, required: bool = False) -> Optional[Path]:
    path_str = os.environ.get(env_var, default)
    if not path_str:
        if required: config_logger.critical(f"Missing required path: {env_var}"); sys.exit(1)
        return None
    try:
        resolved_path = Path(os.path.expanduser(path_str)).resolve(strict=False)
        if check_is_dir and resolved_path.exists() and not resolved_path.is_dir(): raise ValueError(f"Path '{resolved_path}' exists but is not a directory.")
        if check_is_file and resolved_path.exists() and not resolved_path.is_file(): raise ValueError(f"Path '{resolved_path}' exists but is not a file.")
        if required and not resolved_path.exists() and (check_is_dir or check_is_file): raise ValueError(f"Required path '{resolved_path}' does not exist.")
        return resolved_path
    except Exception as e: config_logger.error(f"Error resolving/checking path {env_var} ('{path_str}'): {e}");
    if required: sys.exit(1)
    return None


# --- Pydantic Settings Model ---
class AppSettings(BaseSettings):
    # --- Filesystem Paths ---
    STORAGE_BASE_PATH: Path = Field(description="Host path where encrypted session data directories are stored.")
    METADATA_PATH: Path = Field(description="Host path where session metadata JSON files are stored.")

    # --- GnuPG Configuration ---
    GNUPG_HOME: Optional[Path] = Field(default=None, description="Optional path to the GnuPG home directory if non-standard.")
    GPG_BINARY: Optional[Path] = Field(default=None, description="Optional full path to the gpg executable.")
    SERVICE_GPG_KEYID: str = Field(description="Required GPG Key ID (long format/fingerprint preferred) used BY THE SERVICE to encrypt data FOR ITSELF. The corresponding private key (ideally unpassphrased or agent-managed) must be in the keyring for decryption.")

    # --- Service Limits & Behavior ---
    MAX_SESSION_SIZE_MB: int = Field(default=100, gt=0, description="Maximum total size (MB) allowed for all files within a single session (best-effort check).")
    MAX_FILE_SIZE_MB: int = Field(default=20, gt=0, description="Maximum size (MB) allowed for a single file upload.")
    SESSION_TTL_SECONDS: int = Field(default=3600 * 24, gt=0, description="Time-To-Live in seconds for inactive sessions (checked by cleanup task).")
    ENABLE_INTERNAL_TTL_CLEANUP: bool = Field(default=False, description="Enable the built-in background task for cleaning up TTL-expired sessions.")
    INTERNAL_CLEANUP_INTERVAL_SECONDS: int = Field(default=3600, gt=0, description="Interval (seconds) for the internal cleanup task.")

    # --- Logging & Metrics ---
    LOG_LEVEL: str = Field(default="INFO", description="Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL).")
    METRICS_PORT: int = Field(default=9091, gt=1023, le=65535, description="Port for the Prometheus /metrics endpoint.")

    class Config:
        env_file = '.env'
        env_file_encoding = 'utf-8'
        case_sensitive = False
        extra = 'ignore'

    # --- Validators ---
    @validator('STORAGE_BASE_PATH', 'METADATA_PATH', pre=True)
    def validate_required_paths(cls, v, field):
        if not v: raise ValueError(f"{field.name} is required.")
        # Resolve path but defer existence check/creation to main startup
        return resolve_path(field.name.upper(), v, required=True)

    @validator('GNUPG_HOME', 'GPG_BINARY', pre=True)
    def validate_optional_paths(cls, v, field):
        # Check if file exists if set for binary
        return resolve_path(field.name.upper(), v, check_is_file=(field.name == 'GPG_BINARY'))

    @validator('LOG_LEVEL')
    def check_log_level(cls, v):
        v_upper = v.upper(); valid = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        if v_upper not in valid: raise ValueError(f"Invalid LOG_LEVEL: {v}")
        return v_upper

# --- Load Settings ---
try:
    settings = AppSettings()
    # Manual check for required SERVICE_GPG_KEYID
    if not settings.SERVICE_GPG_KEYID:
         raise ValidationError.from_exception_data("SERVICE_GPG_KEYID is required.", [{"loc": ("SERVICE_GPG_KEYID",), "msg": "Field required"}])
except ValidationError as e:
    config_logger.critical(f"Configuration validation errors:\n{e}")
    sys.exit(1)

# --- Log effective config ---
def get_config_summary() -> Dict[str, Any]:
    """Returns a dictionary summary of the configuration."""
    summary = settings.model_dump()
    for key, val in summary.items():
        if isinstance(val, Path): summary[key] = str(val)
    return summary

config_logger.info("GnuTomb Configuration loaded and validated successfully.")

# --- Constants derived from Config ---
MAX_SESSION_SIZE_BYTES = settings.MAX_SESSION_SIZE_MB * 1024 * 1024
MAX_FILE_SIZE_BYTES = settings.MAX_FILE_SIZE_MB * 1024 * 1024
ALLOWED_FILENAME_REGEX = re.compile(r"^[a-zA-Z0-9._-]+$") # For files within session
MAX_FILENAME_LENGTH = 100
SESSION_ID_REGEX = re.compile(r"^[a-zA-Z0-9-]+$") # Allow UUID format for session IDs
