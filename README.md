# papAIa

This directory contains all the components of a self‑hosted home server solution built with Docker. The system provides various services including web browsing privacy, home automation, AI assistance, content extraction, and document management.

### LocalAI
- Local LLM inference engine
- Runs language models without external API calls
- GPU acceleration support
- Compatible with OpenAI API format

## Architecture Overview

The home server is organized into three main categories:

1. **Infrastructure** - Core networking and proxy services
2. **Services** - Privacy-focused applications and utilities
3. **AI** - Artificial intelligence and automation

All services are orchestrated using Docker Compose and share a common network for secure communication.

## Quick Start

### Prerequisites
- Docker and Docker Compose installed
- At least 8GB RAM recommended
- Linux or WSL2 environment

### Starting Services
```bash
./starths.sh
```

### Stopping Services
```bash
./stophs.sh stop   # Stops containers without removing them
./stophs.sh down   # Stops and removes containers
```

### Environment Setup
1. Copy `.env.example` to `.env` in each service directory
2. Modify the variables according to your needs
3. Some services require API keys for full functionality

## Infrastructure Components

### Nginx Proxy Manager
- Provides reverse proxy capabilities
- Handles SSL certificates with Let's Encrypt
- Web-based administration interface
- Port: 81 (default)

### Keycloak
- Enterprise-grade Single Sign-On (SSO)
- Comprehensive Protocol Support
- Centralized Identity & Access Management
- Customizable User Interfaces

## Service Components

### SearXNG
- Privacy-respecting metasearch engine
- Aggregates results from multiple search providers
- No user tracking or profiling
- Port: 8500 (default)

### Home Assistant
- Home automation platform
- Device integration and control
- Network discovery and monitoring
- Runs in host network mode

### Paperless ngx
- Document Management System
- Full-Text Search Capability
- Automated Processing Pipeline
- Multi-User Collaboration

### Firecrawl
- Web scraping and crawling service
- Converts websites to LLM-ready data
- Includes Playwright for browser automation
- Features queue management with RabbitMQ
- Data storage with PostgreSQL and Redis

### Jina AI
- Embedding and search services
- Text processing and vectorization
- API endpoints for semantic search

## AI Components

### LibreChat
- Chat interface for multiple AI models
- Supports OpenAI, Anthropic, and other providers
- Integrated RAG (Retrieval-Augmented Generation)
- Document search with Meilisearch
- MongoDB for data persistence

### N8N
- 400 + pre‑built integrations & native AI nodes
- Hybrid low‑code & code workflow design
- Self‑hosted for full data sovereignty
- Step‑wise execution & replay

### LiteLLM
- Proxy for various LLM providers
- Unified API interface
- Rate limiting and monitoring
- Prometheus metrics collection

### doc-rag
- RAG pipeline for personal document search
- Syncs documents from WebDAV sources (Nextcloud, SharePoint, …) via rclone
- Extracts and chunks text from PDF, DOCX, DOC, Markdown, plain text (Docling)
- Embeds chunks via LiteLLM and stores vectors in Qdrant
- Exposes `search_documents` and `list_collections` as MCP tools for LibreChat
- `GET /health` and `POST /reindex` endpoints for monitoring and operations
- Port: 8700 (default)

### MCP Services
- Paperless ngx
- doc-rag (semantic document search)

## Management Scripts

### starths.sh
Starts all services in the correct order with proper environment configurations.

### stophs.sh
Stops or removes all running services.

### backuphs.sh
- Creates backups of all Docker volumes
- Automatically cleans up old backups (14-day retention)
- Syncs backups to OneDrive

### restorehs.sh
Restores individual Docker volumes from backup archives.

## Network Security

All services communicate through a dedicated Docker network (`hs-net`) which isolates them from the host network while allowing inter-service communication. Nginx Proxy Manager controls external access and SSL termination.

## Data Persistence

Each service uses Docker named volumes for data persistence. These volumes survive container recreation but are tied to the Docker installation.

## Configuration

Most services can be configured through environment variables defined in `.env` files. Examples are provided in `.env.example` files in each service directory.

## Backup Strategy

The backup system creates gzipped archives of all Docker volumes daily. Backups older than 14 days are automatically deleted to save space. Integration with OneDrive ensures off-site backup storage.
