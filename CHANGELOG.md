# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Release notes are generated automatically by [release-drafter](https://github.com/release-drafter/release-drafter)
based on merged pull requests; this file mirrors the published releases.

## [Unreleased]

<!-- Updated automatically by release-drafter as PRs are merged to `main`. -->

## [0.7.0] - 2026-06-11

### 🚀 Features

- feat: add qdrant-rbac service and LibreChat MCP integration with OIDC token forwarding (#51)
- feat(qdrant-webdav-ingest): add WebDAV → Qdrant ingestion service with MCP interface (#56)
- feat(librechat): optional agents bind-mount from an external directory (#58)
- feat(paperless): make media, export and consume directories configurable (#61)
- feat(paperless): make SSO and login behaviour configurable via .env (#63)
- feat(librechat): optional prompts bind-mount with markdown front matter (#66)
- feat: replace mcp-paperless with oidc-secured paperless-mcp-rbac (#70)

### 🐛 Bug Fixes

- fix(qdrant-rag): consolidate all env vars into root src/.env (#53)
- fix(librechat): defer QdrantRAG MCP init to first per-user call (startup: false) (#54)
- fix: correct qdrant-rbac image name in env example (#72)

### 🛠 Maintenance

- chore: remove doc-rag module from stack (#71)

### 📖 Documentation

- docs: add architecture overview and big-picture diagrams (#59)
- docs: add license and legal documents (#69)
- docs: document v0.7.0 service images in THIRD_PARTY_LICENSES.md (#75, #76)

**Full Changelog**: https://github.com/Fidonis/papaia/compare/v0.6.0...v0.7.0

[Unreleased]: https://github.com/Fidonis/papaia/compare/v0.7.0...HEAD
[0.7.0]: https://github.com/Fidonis/papaia/compare/v0.6.0...v0.7.0
