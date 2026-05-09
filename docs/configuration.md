# Configuration

> **Status:** Draft — to be expanded.

## Configuration files

papAIa is configured via environment variables and per-service `.env` files.

- Root `.env` — global settings shared across services
- Per service: `src/<area>/<service>/.env` — service-specific overrides
- Each service ships an `.env.example` that documents available variables

## Environment variables

<!-- TODO: Sorted table of relevant variables, with defaults and descriptions -->

## Secrets handling

<!-- TODO: Which variables are secrets, where they belong (`.env`, secrets store, GitHub Actions secrets) -->
