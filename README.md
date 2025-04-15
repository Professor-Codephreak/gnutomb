# GnuTomb MCP Service (v1.0.0)

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0) <!-- Assuming Apache 2.0, update if different -->
[![Python Version](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![MCP Version](https://img.shields.io/badge/MCP-Compliant-success.svg)](https://modelcontextprotocol.info/)

---

**A secure, ephemeral storage service accessible via the Model Context Protocol (MCP), using server-side GnuPG encryption.**

Inspired by the concept of [Tomb](https://www.dyne.org/software/tomb/) ("the crypto undertaker"), this service provides temporary, isolated "digital lockboxes" where clients can store files securely. All data is automatically encrypted upon upload and decrypted upon download using a dedicated GPG key managed by the server.

**Key Difference:** This service uses **file-level GPG encryption** and an **MCP API**, not Tomb's LUKS volumes or direct filesystem mounting.

## ✨ Features

*   **API-Driven Secure Storage:** Interact via standard MCP tools.
*   **Server-Side GPG Encryption:** Transparent encryption/decryption using a service-managed key. Clients don't need GPG keys for interaction.
*   **Isolated Sessions:** Each `storage_initialize` call creates a unique, separate storage directory.
*   **Ephemeral Storage:** Sessions expire based on Time-To-Live (TTL) and can be permanently destroyed with `storage_seal`.
*   **Resource Limits:** Configurable file and total session size limits.
*   **Observability:** Prometheus metrics endpoint and structured JSON logging.
*   **Configuration:** Via environment variables / `.env` file using Pydantic.
*   **Optional Internal Cleanup:** Background task for TTL enforcement.

## 🏗️ Project Structure

```plaintext
gnutomb/
├── .env.example          # Example environment configuration file
├── .gitignore            # Standard Python gitignore
├── config.py             # Pydantic models & loading for environment variables
├── gpg_utils.py          # Utilities for interacting with python-gnupg
├── server.py             # Main MCP server application (FastMCP, tools, core logic)
├── requirements.txt      # Python package dependencies
├── install.sh            # Example installation script for Debian 12
├── README.md             # This file: Overview, setup, usage, licensing
└── docs/
    ├── INTRO.md          # High-level introduction to the project
    ├── TECHNICAL.md      # In-depth technical details (architecture, config, API)
    └── USAGE.md          # Guide for client developers using the MCP tools
```
pip install -r requirements.txt
# OR using uv
# uv pip install -r requirements.txt


Service User: Create a dedicated non-root user (e.g., gnutomb).
GPG Key Setup (Crucial):
As the service user, generate a GPG keypair specifically for this service.
Recommendation: Use a key without a passphrase OR configure gpg-agent properly for the service user so passphrases aren't needed interactively.
Example (passphraseless): gpg --batch --passphrase '' --quick-gen-key 'GnuTomb Service <gnutomb@localhost>' default default never
Note the long Key ID or Fingerprint.
Storage Directories:
Create base paths for data and metadata (e.g., /var/lib/gnutomb/sessions, /var/lib/gnutomb/metadata).
Set ownership to the service user (chown -R gnutomb:gnutomb /var/lib/gnutomb).
Set strict permissions (chmod -R 700 /var/lib/gnutomb).
Configure Service:
Copy .env.example to .env.
Edit .env: Set the correct SERVICE_GPG_KEYID (the key generated in step 4). Adjust STORAGE_BASE_PATH and METADATA_PATH if needed. Configure limits, TTL, logging, etc.
Ensure .env permissions are strict (chmod 600 .env).
Run the Service:
# Ensure environment variables loaded (e.g., from .env or systemd EnvironmentFile)
# Example using MCP CLI runner & SSE transport on port 8004
mcp run server.py --transport sse --host 0.0.0.0 --port 8004
Use code with caution.
Bash
(See install.sh and docs/TECHNICAL.md for systemd example).
📖 Usage
Interact with the service using an MCP client library. See docs/USAGE.md for the detailed API reference and workflow examples. Core flow: initialize -> store session_id -> upload/download/list/delete -> seal. Remember to Base64 encode/decode file content on the client side.
🛠️ Technical Details & Limitations
For in-depth information on architecture, configuration, API details, GPG handling, security considerations, and limitations, please refer to docs/TECHNICAL.md. Key limitations include reliance on file-based metadata (less robust than a DB) and the need for reliable GPG key management on the server.
📜 Licensing
GnuTomb MCP Service Code (This Project): Copyright (c) 2025 PYTHAI - Licensed under the Apache License 2.0. (Adjust if needed)
Model Context Protocol (MCP) Specification & SDKs: Licensed under the Apache License 2.0.
python-gnupg: Licensed under the GPLv3 or later. (Check project for specifics)
Python Dependencies: Each dependency (pydantic, prometheus-client, etc.) carries its own open-source license (commonly MIT, Apache 2.0, BSD). Please consult the respective project licenses.
