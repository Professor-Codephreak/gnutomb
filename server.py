#!/usr/bin/env python
# GnuTomb MCP Service - v1.0.0 (Based on Dev Env Service v2.0.0 structure)

# --- Imports ---
import asyncio
import base64
import logging
import os
import sys
import shutil
import uuid
import json
import time
import re
import tempfile
import signal
import threading
from pathlib import Path
from typing import List, Optional, Dict, Any, AsyncGenerator, Tuple, Union
from contextlib import asynccontextmanager, suppress

# --- Dependency Imports ---
try:
    from mcp.server.fastmcp import FastMCP, Context
    from mcp.model import ToolInputError
except ImportError: print("ERROR: modelcontextprotocol library not found.", file=sys.stderr); sys.exit(1)
try: from pythonjsonlogger import jsonlogger
except ImportError: print("ERROR: python-json-logger library not found.", file=sys.stderr); sys.exit(1)
try: from prometheus_client import Counter, Gauge, start_http_server, REGISTRY, PROCESS_COLLECTOR, PLATFORM_COLLECTOR
except ImportError: print("WARN: prometheus-client missing. Metrics disabled.", file=sys.stderr); Counter=Gauge=None; start_http_server=None; REGISTRY=None; PROCESS_COLLECTOR=None; PLATFORM_COLLECTOR=None

# --- Import Local Modules ---
try:
    from config import settings, get_config_summary
    import gpg_utils # Use GPG utils instead of DB/Docker/Proxy
except ImportError as e: print(f"ERROR: Failed to import local module: {e}", file=sys.stderr); sys.exit(1)


# --- Logging Setup ---
logger = logging.getLogger("GnuTombMCPServer") # Changed logger name
try: logger.setLevel(settings.LOG_LEVEL)
except ValueError: logger.setLevel("INFO"); logger.warning(f"Invalid LOG_LEVEL '{settings.LOG_LEVEL}', using INFO.")
logger.propagate = False
logHandler = logging.StreamHandler(sys.stderr)
formatter = jsonlogger.JsonFormatter(
    '%(asctime)s %(levelname)s %(name)s %(message)s [%(pathname)s:%(lineno)d]'
)
logHandler.setFormatter(formatter)
if not logger.handlers: logger.addHandler(logger)


# --- Metrics Initialization ---
if Counter and Gauge and REGISTRY and PROCESS_COLLECTOR and PLATFORM_COLLECTOR:
    with suppress(KeyError): REGISTRY.unregister(PROCESS_COLLECTOR)
    with suppress(KeyError): REGISTRY.unregister(PLATFORM_COLLECTOR)
    MCP_TOOL_CALLS = Counter('gnutomb_mcp_tool_calls_total', 'Total GnuTomb MCP tool calls', ['tool_name', 'status'])
    ACTIVE_SESSIONS = Gauge('gnutomb_active_sessions', 'Number of active GnuTomb sessions') # Changed metric name
    MCP_TOOL_DURATION = Gauge('gnutomb_mcp_tool_duration_seconds', 'Duration of last GnuTomb MCP tool call', ['tool_name'])
    TOOLS = [ # GnuTomb specific tools
        "storage_initialize", "storage_upload", "storage_download",
        "storage_list", "storage_delete", "storage_seal", "storage_disk_usage"
    ]
    for tool in TOOLS:
        MCP_TOOL_CALLS.labels(tool_name=tool, status='success'); MCP_TOOL_CALLS.labels(tool_name=tool, status='failure'); MCP_TOOL_DURATION.labels(tool_name=tool).set(0)
else: MCP_TOOL_CALLS = ACTIVE_SESSIONS = MCP_TOOL_DURATION = None

def metrics_increment_call(tool_name: str, success: bool = True):
    if MCP_TOOL_CALLS: MCP_TOOL_CALLS.labels(tool_name=tool_name, status='success' if success else 'failure').inc()

def metrics_set_last_duration(tool_name: str, duration: float):
     if MCP_TOOL_DURATION: MCP_TOOL_DURATION.labels(tool_name=tool_name).set(duration)

# Update active sessions count based on metadata files (less efficient than DB)
async def metrics_update_active_sessions():
    if ACTIVE_SESSIONS:
        try:
            count = len(list(settings.METADATA_PATH.glob('*.json')))
            ACTIVE_SESSIONS.set(count)
        except Exception as e:
            logger.error("Failed to update active sessions metric.", exc_info=True)


# --- MCP Server ---
mcp = FastMCP("GnuTombService_v1.0.0") # Changed service name

# --- State Management & Locking (File Metadata Based) ---
session_locks: Dict[str, asyncio.Lock] = {}
_global_lock_dict_lock = asyncio.Lock() # Protects session_locks dict
# No semaphore needed as concurrency limit not directly tied to 'running' state easily

# --- Metadata Functions (Atomic Write, Using Files) ---
def get_session_metadata_path(session_id: str) -> Path:
    """Gets metadata path. Validates ID format."""
    # Use stricter regex for session IDs if they are UUIDs
    if not session_id or not settings.SESSION_ID_REGEX.match(session_id):
         raise ToolInputError(f"Invalid session ID format.")
    return settings.METADATA_PATH / f"{session_id}.json"

def write_session_metadata(session_id: str, metadata: Dict[str, Any]):
    """Writes session metadata atomically."""
    metadata_file = get_session_metadata_path(session_id); tmp_file_path = None; fd = -1
    log_extra = {"session_id": session_id, "path": str(metadata_file)}
    try:
        fd, tmp_str = tempfile.mkstemp(dir=settings.METADATA_PATH, prefix=f"{session_id}_", suffix=".tmp"); tmp_file_path = Path(tmp_str)
        with os.fdopen(fd, 'w') as f: json.dump(metadata, f); fd = -1 # Mark fd closed
        os.rename(tmp_file_path, metadata_file)
        logger.debug("Atomically wrote session metadata.", extra=log_extra)
    except Exception as e:
        logger.error(f"Failed write meta atomically for {session_id}", extra=log_extra, exc_info=True)
        if fd != -1: os.close(fd)
        if tmp_file_path and tmp_file_path.exists(): tmp_file_path.unlink(missing_ok=True)
        raise IOError(f"Failed to write session metadata: {e}") from e # Raise IOError for wrapper

def read_session_metadata(session_id: str, check_ttl: bool = True) -> Optional[Dict[str, Any]]:
    """Reads metadata, optionally checks TTL."""
    metadata_file = get_session_metadata_path(session_id)
    if not metadata_file.is_file(): return None
    log_extra = {"session_id": session_id, "path": str(metadata_file)}
    try:
        with open(metadata_file, 'r') as f: metadata = json.load(f)
        required_keys = {"session_id", "session_path", "created_ts", "last_accessed_ts"}
        if not isinstance(metadata, dict) or not required_keys.issubset(metadata.keys()) or metadata["session_id"] != session_id:
            logger.error(f"Invalid/inconsistent metadata structure.", extra=log_extra); return None
        if check_ttl:
            last_accessed = metadata.get('last_accessed_ts', 0)
            if time.time() - last_accessed > settings.SESSION_TTL_SECONDS:
                logger.info(f"Session expired based on TTL.", extra=log_extra | {"last_accessed": last_accessed})
                return None # Session expired
        return metadata
    except (IOError, json.JSONDecodeError) as e: logger.error(f"Failed read/parse metadata.", extra=log_extra, exc_info=True); return None

def delete_session_metadata(session_id: str):
    """Deletes the metadata file."""
    log_extra = {"session_id": session_id}
    try: get_session_metadata_path(session_id).unlink(missing_ok=True); logger.debug("Deleted session metadata file.", extra=log_extra)
    except OSError as e: logger.error("Failed delete metadata file.", extra=log_extra, exc_info=True)


# --- Locking ---
@asynccontextmanager
async def get_session_lock(session_id: str) -> AsyncGenerator[asyncio.Lock, None]:
    """Acquires/releases lock, cleaning stale based on metadata file existence."""
    if not session_id or not settings.SESSION_ID_REGEX.match(session_id): raise ValueError("Invalid session_id format for lock")
    async with _global_lock_dict_lock:
        lock = session_locks.get(session_id)
        metadata_exists = get_session_metadata_path(session_id).is_file() # Check file system
        if lock is not None and not metadata_exists:
             logger.info("Cleaning stale lock for removed session.", extra={"session_id": session_id})
             del session_locks[session_id]; lock = None
        if lock is None: lock = asyncio.Lock(); session_locks[session_id] = lock
    async with lock: yield lock # Lock released by context manager

async def remove_session_lock(session_id: str):
     """Removes lock from dict safely."""
     async with _global_lock_dict_lock:
         if env_id in session_locks: del session_locks[env_id]; logger.debug("Removed session op lock.", extra={"session_id": session_id})


# --- Path Validation ---
def validate_filename(filename: str):
     """Validates filename format and length."""
     if not filename: raise ToolInputError("Filename cannot be empty.", code=ErrorCode.INVALID_INPUT)
     if len(filename) > config.MAX_FILENAME_LENGTH: raise ToolInputError(f"Filename exceeds max length.", code=ErrorCode.INVALID_INPUT)
     if ".." in filename or "/" in filename or "\\" in filename: raise ToolInputError("Invalid characters (e.g., '/', '..') in filename.", code=ErrorCode.INVALID_INPUT)
     if not config.ALLOWED_FILENAME_REGEX.match(filename): raise ToolInputError(f"Filename contains invalid characters.", code=ErrorCode.INVALID_INPUT)

# --- Tool Error Codes Enum ---
class ErrorCode(str, Enum): # Simplified for storage service
    INVALID_INPUT = "INVALID_INPUT"; SESSION_NOT_FOUND = "SESSION_NOT_FOUND"; QUOTA_EXCEEDED = "QUOTA_EXCEEDED"
    FILESYSTEM_ERROR = "FILESYSTEM_ERROR"; GPG_ERROR = "GPG_ERROR"; INTERNAL_ERROR = "INTERNAL_ERROR"

# --- Tool Wrapper ---
@asynccontextmanager
async def _tool_wrapper(tool_name: str, session_id: Optional[str] = None, update_ts: bool = True, **kwargs):
    """Wrapper for metrics, errors, locking, timestamp updates."""
    log_extra = {"tool_name": tool_name, "session_id": session_id} | kwargs
    logger.debug("Tool execution starting.", extra=log_extra)
    start_time = time.monotonic(); success = False
    needs_lock = session_id and tool_name not in ['storage_list', 'storage_disk_usage'] # Read-only ops exclude lock
    lock_context = get_session_lock(session_id) if needs_lock else suppress()
    error_code = ErrorCode.INTERNAL_ERROR; error_msg = "An unexpected internal server error occurred."
    metadata = None # Hold metadata

    try:
        async with lock_context:
             # Pre-fetch metadata for operations needing an existing session
             if session_id and tool_name not in ['storage_initialize']:
                 metadata = read_session_metadata(session_id) # Checks TTL by default
                 if not metadata: raise ToolInputError(f"Session '{session_id}' not found or expired.", code=ErrorCode.SESSION_NOT_FOUND)
             yield metadata # Pass metadata or None to the tool logic
             success = True
    except ToolInputError as e: error_code=getattr(e,'code',ErrorCode.INVALID_INPUT); error_msg=e.message; logger.warning(f"Tool '{tool_name}' failed: {error_msg}", extra=log_extra|{"code":error_code.value})
    except (IOError, OSError) as e: error_code=ErrorCode.FILESYSTEM_ERROR; error_msg="Server filesystem error."; logger.error(f"Tool fail: {error_msg}", extra=log_extra, exc_info=True)
    # GPG errors are caught inside gpg_utils and re-raised as ToolInputError usually
    except Exception as e: error_code=ErrorCode.INTERNAL_ERROR; error_msg="An unexpected server error occurred."; logger.error(f"Tool fail: Unexpected error.", extra=log_extra, exc_info=True)
    finally:
        duration = time.monotonic() - start_time; metrics_set_last_duration(tool_name, duration); metrics_increment_call(tool_name, success=success); log_extra_final = log_extra | {"duration_s": round(duration, 3), "success": success}
        if success: logger.info(f"Tool '{tool_name}' success.", extra=log_extra_final);
        else: logger.info(f"Tool '{tool_name}' final status: FAILED.", extra=log_extra_final | {"error_code": error_code.value})
        # Update timestamp only on success and if requested
        if session_id and metadata and update_ts and success: # Check metadata exists too
            try:
                # Ensure write happens outside lock if read ops don't lock
                if needs_lock: update_last_accessed(session_id, metadata) # Safe inside lock
                else: # Acquire lock just for timestamp update if needed
                     async with get_session_lock(session_id): update_last_accessed(session_id, metadata)
            except Exception as ts_e: logger.error("Failed timestamp update.", extra=log_extra, exc_info=True)

        if not success: raise ToolInputError(error_msg, code=error_code) # Raise consistent error


# --- Filesystem Helpers ---
async def calculate_dir_size(path: Path) -> int:
    """Calculates total size. Runs potentially blocking calls in thread."""
    def _sum_size(): # Synchronous helper
        total_size = 0
        try:
            for item in path.rglob('*'):
                try:
                    if item.is_file(follow_symlinks=False): total_size += item.stat(follow_symlinks=False).st_size
                except OSError: pass # Skip files we cannot stat
        except OSError as list_err: raise IOError(f"Cannot list directory: {list_err}") from list_err # Raise IOError
        return total_size
    return await asyncio.to_thread(_sum_size)

def update_last_accessed(session_id: str, metadata: Dict[str, Any]):
    """Updates the last_accessed timestamp atomically."""
    if not metadata: return
    metadata['last_accessed_ts'] = time.time()
    try:
        write_session_metadata(session_id, metadata) # Use atomic write
        logger.debug("Atomically updated last accessed timestamp.", extra={"session_id": session_id})
    except (IOError, OSError) as e: # Catch errors from write_session_metadata
        logger.error(f"Failed to update last_accessed timestamp.", extra={"session_id": session_id}, exc_info=True)

# --- MCP Tools ---

@mcp.tool()
async def storage_initialize(ctx: Context) -> str:
    """ Initializes a new secure GPG-encrypted storage session. """
    async with _tool_wrapper("storage_initialize", update_ts=False) as _: # No existing session ID yet
        max_retries = 3
        for attempt in range(max_retries):
            session_id = str(uuid.uuid4())
            log_extra = {"session_id_candidate": session_id, "attempt": attempt + 1}
            session_path = config.settings.STORAGE_BASE_PATH / session_id
            metadata_file = get_session_metadata_path(session_id) # Validates format

            # Lock before check/create filesystem items
            async with get_session_lock(session_id):
                if metadata_file.exists() or session_path.exists():
                     logger.warning(f"Session collision detected within lock. Retrying...", extra=log_extra)
                     continue # Retry with new UUID

                try:
                    await asyncio.to_thread(session_path.mkdir, mode=0o700, parents=True) # Run mkdir in thread
                    ts = time.time()
                    metadata = { "session_id": session_id, "session_path": str(session_path),
                                 "created_ts": ts, "last_accessed_ts": ts }
                    write_session_metadata(session_id, metadata) # Atomic write
                    logger.info(f"Initialized secure storage session {session_id}", extra=metadata)
                    await metrics_update_active_sessions() # Update gauge
                    return session_id # Success
                except (OSError, IOError) as e:
                     logger.error(f"Failed to create session components.", extra=log_extra, exc_info=True)
                     # Cleanup attempt (run blocking FS ops in thread)
                     with suppress(Exception): await asyncio.to_thread(lambda: session_path.rmdir() if session_path.exists() else None)
                     with suppress(Exception): await asyncio.to_thread(lambda: metadata_file.unlink(missing_ok=True))
                     raise ToolInputError("Failed init session storage: FS error.", code=ErrorCode.FILESYSTEM_ERROR) from e

        # If loop finishes, all retries failed
        logger.critical(f"Failed init session after {max_retries} collision retries.")
        raise ToolInputError("Failed init session: internal collision error.", code=ErrorCode.INTERNAL_ERROR)


@mcp.tool()
async def storage_upload(session_id: str, filename: str, content_base64: str):
    """ Uploads, Base64 decodes, GPG encrypts, and stores a file. """
    # Wrapper gets metadata, handles lock, metrics, errors, timestamp update
    async with _tool_wrapper("storage_upload", session_id=session_id, filename_raw=filename) as metadata:
        session_path = Path(metadata["session_path"]) # Get path from metadata provided by wrapper
        validate_filename(filename) # Check filename safety
        log_extra = {"session_id": session_id, "filename": filename}

        # Decode Base64
        try: plaintext_bytes = base64.b64decode(content_base64, validate=True)
        except base64.binascii.Error as e: raise ToolInputError(f"Invalid base64 encoding.", code=ErrorCode.INVALID_INPUT) from e
        file_size_bytes = len(plaintext_bytes)
        if file_size_bytes > config.MAX_FILE_SIZE_BYTES: raise ToolInputError(f"File exceeds max size {config.settings.MAX_FILE_SIZE_MB} MB.", code=ErrorCode.QUOTA_EXCEEDED)

        # Check total session size limit (best effort) - Run calc in thread
        current_size_bytes = await calculate_dir_size(session_path)
        if current_size_bytes + file_size_bytes > config.MAX_SESSION_SIZE_BYTES: raise ToolInputError(f"Upload exceeds session limit {config.settings.MAX_SESSION_SIZE_MB} MB.", code=ErrorCode.QUOTA_EXCEEDED)

        # Encrypt data using GPG utils - This might block, run in thread
        encrypted_bytes = await asyncio.to_thread(gpg_utils.encrypt_data, plaintext_bytes) # Can raise ToolInputError(code=GPG_ERROR)

        # Write encrypted data atomically
        encrypted_target_path = session_path / f"{filename}.gpg"
        tmp_file_path = None; fd = -1
        try:
            fd, tmp_str = tempfile.mkstemp(dir=session_path, prefix=f"{filename}_", suffix=".gpg.tmp")
            tmp_file_path = Path(tmp_str)
            with os.fdopen(fd, "wb") as f: f.write(encrypted_bytes); fd = -1 # Mark closed
            os.rename(tmp_file_path, encrypted_target_path) # Atomic rename
        except (OSError, IOError) as e:
            if fd != -1: os.close(fd)
            if tmp_file_path and tmp_file_path.exists(): tmp_file_path.unlink(missing_ok=True)
            raise # Re-raise IOError/OSError for wrapper


@mcp.tool()
async def storage_download(session_id: str, filename: str) -> str:
    """ Reads encrypted file, decrypts, Base64 encodes, and returns content. """
    async with _tool_wrapper("storage_download", session_id=session_id, filename_raw=filename) as metadata:
        session_path = Path(metadata["session_path"])
        validate_filename(filename)
        encrypted_source_path = session_path / f"{filename}.gpg"
        log_extra = {"session_id": session_id, "filename": filename, "path": str(encrypted_source_path)}

        if not await asyncio.to_thread(encrypted_source_path.is_file): # Run potentially blocking FS call in thread
            raise ToolInputError(f"File not found: {filename}", code=ErrorCode.INVALID_INPUT)

        # Read encrypted data - run blocking read in thread
        ciphertext_bytes = await asyncio.to_thread(encrypted_source_path.read_bytes)

        # Decrypt data - run blocking GPG call in thread
        plaintext_bytes = await asyncio.to_thread(gpg_utils.decrypt_data, ciphertext_bytes) # Raises ToolInputError(code=GPG_ERROR)

        # Encode plaintext to base64 (CPU bound, but fast enough usually)
        plaintext_base64 = base64.b64encode(plaintext_bytes).decode('ascii')
        return plaintext_base64


@mcp.tool()
async def storage_list(session_id: str) -> List[str]:
    """ Lists original filenames (without .gpg) in the session. """
    async with _tool_wrapper("storage_list", session_id=session_id) as metadata:
        session_path = Path(metadata["session_path"])
        filenames = []
        # Run potentially blocking scandir/stat in thread
        def _list_dir():
            try:
                for item in os.scandir(session_path):
                    if item.is_file(follow_symlinks=False) and item.name.endswith(".gpg"):
                        original_name = item.name[:-4]
                        # Basic check on listed name format? Optional.
                        if config.ALLOWED_FILENAME_REGEX.match(original_name):
                             filenames.append(original_name)
                        else: logger.warning("Skipping file with unexpected name during list.", extra={"session_id": session_id, "malformed_name": item.name})
            except OSError as e: raise IOError(f"Failed listing directory: {e}") from e # Wrap in IOError for wrapper
        await asyncio.to_thread(_list_dir)
        return filenames


@mcp.tool()
async def storage_delete(session_id: str, filename: str):
    """ Deletes a specific encrypted file from the session. """
    async with _tool_wrapper("storage_delete", session_id=session_id, filename_raw=filename) as metadata:
        session_path = Path(metadata["session_path"])
        validate_filename(filename)
        encrypted_target_path = session_path / f"{filename}.gpg"
        log_extra = {"session_id": session_id, "filename": filename, "path": str(encrypted_target_path)}

        # Run blocking unlink in thread
        def _delete_file():
             try: encrypted_target_path.unlink(missing_ok=True) # Idempotent
             except OSError as e: raise IOError(f"Failed to delete file: {e}") from e # Wrap in IOError

        await asyncio.to_thread(_delete_file)
        logger.info("Processed delete request.", extra=log_extra)


@mcp.tool()
async def storage_seal(session_id: str):
    """ Securely seals (deletes) the session directory and metadata. """
    # update_ts=False because session is being deleted
    async with _tool_wrapper("storage_seal", session_id=session_id, update_ts=False) as metadata:
        # Metadata existence already checked by wrapper before lock
        log_extra = {"session_id": session_id}
        session_path = Path(metadata["session_path"])
        log_extra["data_path"] = str(session_path)

        logger.warning(f"Sealing storage session {session_id}...", extra=log_extra) # Warning level for destructive op
        deleted_data = False
        try:
            # Delete data directory robustly in thread
            if await asyncio.to_thread(session_path.exists):
                if not await asyncio.to_thread(session_path.is_dir): # Check type before rmtree
                     logger.error("Session path exists but is not a directory during seal!", extra=log_extra)
                     await asyncio.to_thread(session_path.unlink, missing_ok=True) # Try deleting as file
                else:
                     await asyncio.to_thread(shutil.rmtree, session_path, ignore_errors=False) # Raise errors
                logger.info(f"Deleted session data directory.", extra=log_extra)
            deleted_data = True
        except (OSError, IOError) as e: # Catch FS errors from rmtree/unlink/exists
            logger.error(f"Failed to fully delete session data directory: {e}", extra=log_extra, exc_info=True)
            # Don't delete metadata if data deletion failed
            raise ToolInputError(f"Failed to seal storage session data.", code=ErrorCode.FILESYSTEM_ERROR) from e
        finally:
             # Delete metadata file only if data deletion succeeded or dir didn't exist
             if deleted_data:
                  delete_session_metadata(session_id) # This logs errors but doesn't raise

    # Remove internal lock entry *after* releasing context lock from wrapper
    await remove_session_lock(session_id)
    await metrics_update_active_sessions() # Update gauge
    logger.warning(f"Successfully sealed storage session {session_id}", extra=log_extra)


@mcp.tool()
async def storage_disk_usage(session_id: str) -> Dict[str, Any]:
    """Calculates approximate disk usage for the session's volume."""
    # update_ts=False as it's a read-only check
    async with _tool_wrapper("storage_disk_usage", session_id=session_id, update_ts=False) as metadata:
        session_path = Path(metadata["session_path"])
        if not await asyncio.to_thread(session_path.is_dir):
             raise ToolInputError("Env consistency error (host path missing/not dir).", code=ErrorCode.FILESYSTEM_ERROR)
        usage_bytes = await calculate_dir_size(session_path) # Already runs in thread, raises IOError
        usage_mb = round(usage_bytes / (1024 * 1024), 2)
        return {"usage_bytes": usage_bytes, "usage_mb": usage_mb, "limit_mb": settings.MAX_SESSION_SIZE_MB}


# --- Integrated TTL Cleanup Task ---
_cleanup_task: Optional[asyncio.Task] = None
async def _ttl_cleanup_loop():
    """Background task to periodically check and destroy expired sessions."""
    logger.info("Internal TTL Cleanup Task started.", extra={"interval_s": settings.INTERNAL_CLEANUP_INTERVAL_SECONDS})
    while True:
        try:
            await asyncio.sleep(settings.INTERNAL_CLEANUP_INTERVAL_SECONDS)
            logger.info("Running internal TTL cleanup check...")
            sessions_to_cleanup = []
            # Scan metadata directory (potentially blocking on large number of files)
            try:
                current_time = time.time()
                for meta_file in settings.METADATA_PATH.glob('*.json'):
                    session_id = meta_file.stem
                    # Basic check before reading potentially large number of files
                    if not settings.SESSION_ID_REGEX.match(session_id): continue
                    metadata = read_session_metadata(session_id, check_ttl=False) # Read without TTL check first
                    if metadata and current_time - metadata.get('last_accessed_ts', 0) > settings.SESSION_TTL_SECONDS:
                        sessions_to_cleanup.append(session_id)
            except OSError as scan_err: logger.error("Cleanup task: Error scanning metadata dir.", exc_info=True); continue

            if not sessions_to_cleanup: logger.info("Cleanup task: No expired sessions found."); continue

            logger.warning(f"Cleanup task: Found {len(sessions_to_cleanup)} expired sessions.", extra={"expired_ids": sessions_to_cleanup})
            successful_cleanups = 0
            for env_id in sessions_to_cleanup: # Use env_id consistently
                 log_extra_c = {"session_id": env_id} # Use session_id in log
                 try:
                      logger.info("Cleanup task: Attempting to seal expired session.", extra=log_extra_c)
                      # Call storage_seal directly - it handles locking etc.
                      await asyncio.wait_for(storage_seal(env_id), timeout=120.0) # Timeout for seal
                      successful_cleanups += 1
                 except asyncio.TimeoutError: logger.error(f"Cleanup task: Timeout sealing session.", extra=log_extra_c)
                 except asyncio.CancelledError: logger.warning("Cleanup task cancelled during seal.", extra=log_extra_c); raise
                 except Exception as destroy_err: logger.error(f"Cleanup task: Error sealing session.", exc_info=destroy_err, extra=log_extra_c)
            logger.info(f"Cleanup task cycle finished. Attempted: {len(sessions_to_cleanup)}, Succeeded: {successful_cleanups}", extra={"total": len(sessions_to_cleanup), "success": successful_cleanups})
            await metrics_update_active_sessions() # Update metrics after batch
        except asyncio.CancelledError: logger.info("TTL cleanup task stopping."); break
        except Exception as loop_err: logger.error("Unexpected error in TTL cleanup loop.", exc_info=loop_err)


# --- Graceful Shutdown Handling ---
_shutdown_requested = asyncio.Event()
def _handle_sigterm(sig, frame):
    logger.warning(f"Received signal {sig}. Initiating graceful shutdown...", extra={"signal": sig})
    if not _shutdown_requested.is_set(): _shutdown_requested.set()
    else: logger.warning("Shutdown already requested.")

async def _cleanup_active_sessions():
    """Attempts to seal all known active sessions during shutdown."""
    logger.warning("Attempting cleanup of active sessions during shutdown...")
    sessions_to_cleanup = []
    # Scan metadata directory for existing sessions
    try: sessions_to_cleanup = [f.stem for f in settings.METADATA_PATH.glob('*.json') if settings.SESSION_ID_REGEX.match(f.stem)]
    except Exception as e: logger.error("Error scanning metadata during shutdown cleanup.", exc_info=True); return

    if not sessions_to_cleanup: logger.info("No active sessions found for shutdown cleanup."); return
    logger.info(f"Found {len(sessions_to_cleanup)} sessions to clean up: {sessions_to_cleanup}")
    cleanup_tasks = [storage_seal(session_id) for session_id in sessions_to_cleanup]
    results = await asyncio.gather(*cleanup_tasks, return_exceptions=True)
    for session_id, result in zip(sessions_to_cleanup, results):
        log_extra_cleanup = {"session_id": session_id}
        if isinstance(result, Exception) and not isinstance(result, asyncio.CancelledError): logger.error(f"Error during shutdown cleanup.", extra=log_extra_cleanup, exc_info=result)
        else: logger.info(f"Shutdown cleanup processed for session.", extra=log_extra_cleanup)


# --- Main Execution ---
async def main():
    global _cleanup_task
    logger.info("Starting GnuTomb MCP Server (v1.0.0) with configuration.", extra={"config": get_config_summary()})

    # --- Start Prometheus HTTP Server ---
    metrics_thread = None
    if start_http_server:
        try: metrics_thread = threading.Thread(target=start_http_server, args=(settings.METRICS_PORT,), daemon=True); metrics_thread.start(); logger.info(f"Prometheus server started: {settings.METRICS_PORT}")
        except Exception as e: logger.error(f"Failed start Prometheus server.", exc_info=True)
    else: logger.warning("Metrics endpoint disabled.")

    # --- Initialize GPG ---
    try: gpg_utils.setup_gpg() # Uses settings internally
    except RuntimeError as e: logger.critical(f"GPG setup failed: {e}. Exiting."); sys.exit(1)

    # --- Check/Create Directories ---
    try:
        check_create_directory(settings.STORAGE_BASE_PATH, "Storage Base", 0o700)
        check_create_directory(settings.METADATA_PATH, "Metadata", 0o700)
    except SystemExit: sys.exit(1) # Exit if check/create failed critically

    # --- Setup Signal Handlers ---
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM): loop.add_signal_handler(sig, _handle_sigterm, sig, None)

    # --- Start Optional Internal Cleanup Task ---
    if settings.ENABLE_INTERNAL_TTL_CLEANUP:
        _cleanup_task = asyncio.create_task(_ttl_cleanup_loop(), name="TTLCleanupTask")
        logger.info("Internal TTL cleanup task started.")
    else: logger.info("Internal TTL cleanup task disabled.")

    server_task = None
    try: # --- Run MCP Server ---
        if hasattr(mcp, 'run_async'): server_task = asyncio.create_task(mcp.run_async(), name="MCPServerRun")
        else: raise NotImplementedError("MCP SDK needs run_async.")
        await metrics_update_active_sessions() # Initial metrics update
        await _shutdown_requested.wait()
        logger.info("Shutdown requested...")
    except asyncio.CancelledError: logger.info("Main task cancelled.")
    finally: # --- Graceful Shutdown ---
        logger.info("Initiating shutdown procedures...")
        if _cleanup_task and not _cleanup_task.done(): logger.info("Cancelling cleanup..."); _cleanup_task.cancel(); await asyncio.sleep(0.1); await _cleanup_task
        logger.info("Initiating active session cleanup..."); try: await asyncio.wait_for(_cleanup_active_sessions(), 30.0)
        except Exception: logger.error("Error during session cleanup.", exc_info=True)
        if server_task and not server_task.done(): logger.info("Cancelling server..."); server_task.cancel(); await asyncio.sleep(0.1); await server_task
        # No DB or HTTP client to close for GnuTomb

if __name__ == "__main__":
    try: asyncio.run(main())
    except KeyboardInterrupt: logger.info("KeyboardInterrupt received.")
    except SystemExit as e: logger.info(f"System exit: {e.code}"); sys.exit(e.code or 0)
    except NotImplementedError as e: logger.critical(f"Startup failed: {e}"); sys.exit(1)
    except Exception as e: logger.critical("Unhandled exception in main execution.", exc_info=True); sys.exit(1)
    finally: logger.info("GnuTomb MCP Server process exiting.")
