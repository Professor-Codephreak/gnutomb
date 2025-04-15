# Usage Guide: GnuTomb MCP Service

**Version:** 1.0.0

## Introduction

This guide explains how to use the GnuTomb MCP Service client-side. This service provides temporary, secure storage spaces where files are automatically encrypted on the server using GnuPG.

Think of it as requesting a temporary, encrypted "digital lockbox" via an API.

Refer to `docs/TECHNICAL.md` for detailed architecture, configuration, and setup instructions for the *server*.

## Prerequisites for Clients

*   **MCP Client Library:** Your application needs an MCP client library (e.g., `modelcontextprotocol` for Python).
*   **Connection Details:** The MCP endpoint address (e.g., SSE URL or stdio command) for the running GnuTomb service.
*   **Authorization (Potentially):** Your client might need credentials handled by the MCP transport/gateway.

## Core Workflow

1.  **Connect:** Establish an MCP connection to the GnuTomb service.
2.  **Initialize:** Call `storage_initialize` to create a new secure session space.
3.  **Store `session_id`:** Securely store the returned `session_id` string. This ID is needed for all further interactions with *this specific* storage space.
4.  **Interact:** Use the `session_id` with other tools:
    *   `storage_upload`: Store a file (client must Base64 encode content).
    *   `storage_download`: Retrieve a file (client must Base64 decode content).
    *   `storage_list`: See stored filenames.
    *   `storage_delete`: Remove a specific file.
    *   `storage_disk_usage`: Check approximate space used.
5.  **Seal (Crucial):** Call `storage_seal` with the `session_id` when finished to permanently destroy the session and its encrypted data on the server.
6.  **Handle Errors:** Expect `ToolInputError` for issues (invalid ID, file not found, quota, server problems). Check `error.message` and potentially `error.code`.
7.  **Disconnect:** Close the MCP connection.

## MCP Tool Reference (v1.0.0)

*(Tools are called via your MCP client, e.g., `client.execute_tool("tool_name", inputs={...})`)*

---

*   **`storage_initialize() -> str`**
    *   Creates a new, isolated, secure storage session.
    *   **Returns:** A unique `session_id` (string, typically UUID format).

*   **`storage_upload(session_id: str, filename: str, content_base64: str)`**
    *   Uploads file content to the specified session. Content is GPG encrypted by the server using its key before saving.
    *   `session_id`: The ID from `storage_initialize`.
    *   `filename`: Desired filename (alphanumeric, `.`, `_`, `-` allowed, max length 100).
    *   `content_base64`: Raw file content **must** be Base64 encoded by the client.
    *   *Errors:* `SESSION_NOT_FOUND`, `INVALID_INPUT` (bad filename/base64), `QUOTA_EXCEEDED` (file or session size limit), `GPG_ERROR`, `FILESYSTEM_ERROR`, `INTERNAL_ERROR`.

*   **`storage_download(session_id: str, filename: str) -> str`**
    *   Downloads a file from the session. Server decrypts the file content.
    *   `session_id`: The session ID.
    *   `filename`: Name of the file to download.
    *   **Returns:** Decrypted file content, Base64 encoded. **Client must decode this.**
    *   *Errors:* `SESSION_NOT_FOUND`, `INVALID_INPUT` (bad filename, file not found), `GPG_ERROR`, `FILESYSTEM_ERROR`, `INTERNAL_ERROR`.

*   **`storage_list(session_id: str) -> List[str]`**
    *   Lists the original names of files stored in the session.
    *   `session_id`: The session ID.
    *   **Returns:** A list of strings (filenames).
    *   *Errors:* `SESSION_NOT_FOUND`, `FILESYSTEM_ERROR`, `INTERNAL_ERROR`.

*   **`storage_delete(session_id: str, filename: str)`**
    *   Deletes a specific file from the session. Idempotent if the file doesn't exist.
    *   `session_id`: The session ID.
    *   `filename`: Name of the file to delete.
    *   *Errors:* `SESSION_NOT_FOUND`, `INVALID_INPUT` (bad filename), `FILESYSTEM_ERROR`, `INTERNAL_ERROR`.

*   **`storage_seal(session_id: str)`**
    *   Permanently destroys the specified session and all its encrypted contents on the server. The `session_id` becomes invalid. Idempotent. **Use this for cleanup.**
    *   `session_id`: The session ID to destroy.
    *   *Errors:* `INVALID_INPUT` (bad session ID format), `FILESYSTEM_ERROR` (if deletion fails), `INTERNAL_ERROR`.

*   **`storage_disk_usage(session_id: str) -> Dict`**
    *   Calculates approximate total disk usage of the *encrypted* files within the session volume on the host.
    *   `session_id`: The session ID.
    *   **Returns:** `{"usage_bytes": int, "usage_mb": float, "limit_mb": int}` (limit is `MAX_SESSION_SIZE_MB` config).
    *   *Errors:* `SESSION_NOT_FOUND`, `FILESYSTEM_ERROR`, `INTERNAL_ERROR`.

## Error Codes

`ToolInputError` exceptions may contain an `error.code` attribute with one of the following string values:

*   `INVALID_INPUT`: Badly formatted arguments (filename, base64, session ID format, etc.).
*   `SESSION_NOT_FOUND`: The provided `session_id` is invalid, expired, or already sealed.
*   `QUOTA_EXCEEDED`: Upload failed due to file size (`MAX_FILE_SIZE_MB`) or total session size (`MAX_SESSION_SIZE_MB`) limit.
*   `FILESYSTEM_ERROR`: An error occurred during server-side file operations (read, write, delete, list). Check server logs.
*   `GPG_ERROR`: An error occurred during server-side GPG encryption or decryption. Check server logs. Likely indicates server key issue or corrupted data.
*   `INTERNAL_ERROR`: An unexpected server-side error occurred. Check server logs.

## Important Client Considerations

*   **Session Lifecycle:** Sessions are temporary. Store the `session_id` and **always call `storage_seal`** when done. Do not rely solely on server TTL cleanup.
*   **Base64:** You MUST encode data before `storage_upload` and decode data after `storage_download`.
*   **Encryption Scope:** Data is encrypted *at rest* on the server using the *server's* GPG key. Data is decrypted before being sent back to the client. MCP transport security (e.g., TLS for SSE) is separate and important for protecting data *in transit*. This service doesn't encrypt data for external recipients.
*   **Size Limits:** Adhere to server-configured file and session size limits.
*   **Idempotency:** `storage_delete` and `storage_seal` are idempotent.
