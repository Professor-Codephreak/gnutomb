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
