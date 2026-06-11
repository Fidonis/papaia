# Architecture — Big Picture

> **Status:** Complete · **Stack version:** 0.7.0

```mermaid
flowchart TD
    USER(["👤  User / API client"])

    ING["**Ingress**\ne.g. Nginx Proxy Manager"]

    AUTH["**Identity & Auth**\ne.g. Keycloak · oauth2-proxy"]

    APP["**Application Services**\ne.g. LibreChat · Paperless-ngx"]

    TOOL["**AI Tooling & MCP**\ne.g. LiteLLM · doc-rag"]

    DATA[("**Persistence**\ne.g. PostgreSQL · Qdrant")]

    USER  -->  ING
    ING   -->  AUTH
    AUTH  -->  APP
    APP   -->  TOOL
    TOOL  -->  DATA
```

## Layer overview

| # | Layer | Responsibility |
|---|-------|----------------|
| 1 | **Ingress** | TLS termination, reverse proxy, certificate management |
| 2 | **Identity & Auth** | OIDC authentication, forward-auth for non-OIDC services |
| 3 | **Application Services** | End-user features: chat, document management, workflows, search, dashboard |
| 4 | **AI Tooling & MCP** | LLM routing, RAG pipelines, model inference, MCP tool endpoints |
| 5 | **Persistence** | Durable storage: relational databases, vector stores, message queues |
