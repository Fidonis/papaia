# Architecture

> **Status:** Draft — to be expanded.

## Overview

papAIa is a self-hosted, OIDC-secured Docker Compose stack that combines AI tooling (LiteLLM, LibreChat, doc-rag, LocalAI) with infrastructure and productivity services (Keycloak, oauth2-proxy, Nginx, Paperless-ngx, n8n, SearXNG, Homepage).

## Service catalog

<!-- TODO: Table of all services with role, default port, and auth mechanism -->

## Authentication topology

<!-- TODO: Description of the OIDC flow with Keycloak as IdP and oauth2-proxy sidecars guarding services without native OIDC -->

## Data flows

<!-- TODO: e.g. doc-rag ingester → Qdrant → LiteLLM → LibreChat -->

## Networking

<!-- TODO: Internal Docker network, reverse-proxy setup, `host.docker.internal` pattern for macOS Docker Desktop -->

## Persistence

<!-- TODO: Which service uses which volume, backup concept -->
