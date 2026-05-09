# AI Services

This directory contains various AI services configured for local development and deployment using Docker Compose.

## Configuration

Before starting any service, make sure to:
1. Copy the `.env.example` file to `.env`
2. Update the `.env` file with your actual configuration values
3. Review and adjust any service-specific configuration files

## Architecture

These services work together to provide a complete AI development environment:
- LibreChat serves as the main UI for interacting with various AI models
- LiteLLM acts as a proxy and load balancer for different LLM providers
- MCP services extend functionality with specialized capabilities (search, document processing)

## Services Overview

### LocalAI
A self-hosted AI inference engine that runs large language models locally without requiring external API services.

**Configuration Files:**
- `docker-compose.yml`: Docker Compose configuration
- `.env.example`: Example environment variables
- `models/`: Directory for storing downloaded models

### LibreChat
A reverse-engineered ChatGPT UI that allows you to use multiple AI providers through a single interface.

**Configuration Files:**
- `docker-compose.yml`: Docker Compose configuration
- `.env`: Environment variables
- `.env.example`: Example environment variables
- `librechat.yaml`: Main configuration file

### LiteLLM
A proxy server that provides a unified API interface for various LLM providers (OpenAI, Anthropic, Hugging Face, etc.).

**Configuration Files:**
- `docker-compose.yml`: Docker Compose configuration
- `.env`: Environment variables
- `.env.example`: Example environment variables
- `config.yaml`: Main configuration file
- `prometheus.yml`: Monitoring configuration

### N8N
Self-hosted workflow automation tool with a visual editor and a large library of integrations.
**Configuration Files:**
- `docker-compose.yml`: Docker Compose configuration
- `.env`: Environment variables
- `.env.example`: Example environment variables


### MCP DuckDuckGo
A Model Context Protocol (MCP) service that enables searching DuckDuckGo for information.

**Configuration Files:**
- `docker-compose.yml`: Docker Compose configuration
- `.env`: Environment variables
- `.env.example`: Example environment variables

### MCP Paperless
A Model Context Protocol (MCP) service that enables retrieving and managing documents from Paperless NGX.

**Configuration Files:**
- `docker-compose.yml`: Docker Compose configuration
- `.env`: Environment variables
- `.env.example`: Example environment variables

**Key Features:**
- Search documents stored in Paperless NGX
- Retrieve document content and metadata
- Integration with LibreChat for document‑based conversations
- Secure API access using Paperless API keys

### doc-rag
A self-contained RAG (Retrieval-Augmented Generation) pipeline that indexes documents from WebDAV sources (e.g. Nextcloud) and exposes semantic search as MCP tools.

**Configuration Files:**
- `docker-compose.yml`: Docker Compose configuration
- `.env`: Environment variables (WebDAV credentials, LiteLLM key)
- `.env.example`: Template with all variables documented

**Key Features:**
- Multi-source WebDAV sync via rclone; source-agnostic ingestion pipeline
- Text extraction from PDF, DOCX, DOC, Markdown, and plain text (Docling)
- Heading-aware chunking with word-count overflow fallback
- Batch embedding via LiteLLM; mtime index persisted in SQLite across restarts
- Automatic cleanup of vectors for deleted files
- MCP tools `search_documents` and `list_collections` consumed by LibreChat
- `GET /health` and `POST /reindex` HTTP endpoints for operations

