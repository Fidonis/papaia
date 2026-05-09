# Services

This directory contains Docker Compose configurations for various services used in the project.

## Table of Contents
- [SearXNG](#searxng)
- [Firecrawl](#firecrawl)
- [Paperless NGX](#paperless-ngx)
- [Home Assistant](#home-assistant)
- [Jina AI](#jina-ai)

## SearXNG

[SearXNG](https://github.com/searxng/searxng) is a privacy-respecting metasearch engine.

### Configuration

Before starting the service, copy the `.env-example` file to `.env` and adjust the values as needed:

```bash
cp .env-example .env
```

Key environment variables to configure:
- `SEARXNG_EXT_PORT`: External port to access the SearXNG web interface (default: 8500)

Additionally, you can customize the search behavior by modifying the settings file. Copy the example settings:

```bash
# After starting the service at least once
docker cp searxng:/etc/searxng/settings.yml ./settings.yml
# Edit settings.yml as needed
# Then copy back to the volume
docker cp ./settings.yml searxng:/etc/searxng/settings.yml
# Restart the service
docker-compose restart
```

### Usage

Start the service:

```bash
docker-compose up -d
```

Access the web interface at `http://localhost:8500` (or your configured port).

## Firecrawl

[Firecrawl](https://firecrawl.dev) is a service for crawling and converting web pages to markdown or structured data.

### Configuration

Before starting the service, copy the `.env-example` file to `.env` and adjust the values as needed:

```bash
cp .env-example .env
```

Key environment variables to configure:
- `OPENAI_API_KEY`: Your OpenAI API key for LLM processing
- `PORT`: External port to access the Firecrawl API (default: 3002)

### Usage

Start the service:

```bash
docker-compose up -d
```

Access the API at `http://localhost:3002` (or your configured port).

### Components

The Firecrawl service consists of multiple containers:
- `firecrawl`: Main API service
- `fc-playwright-service`: Browser automation service
- `fc-redis`: Redis cache/database
- `fc-rabbitmq`: Message queue
- `fc-nuq-postgres`: PostgreSQL database

## Home Assistant

[Home Assistant](https://www.home-assistant.io/) is an open-source home automation platform.

### Configuration

Before starting the service, copy the `.env-example` file to `.env` and adjust the values as needed:

```bash
cp .env-example .env
```

### Usage

Start the service:

```bash
docker-compose up -d
```

Access the Home Assistant UI at `http://localhost:8123`.

Note: Home Assistant uses host networking mode, which means it has direct access to the host network interfaces.

## Jina AI

[Jina AI](https://jina.ai/) compatible reranker service for improving search result relevance.

### Configuration

Before starting the service, copy the `.env-example` file to `.env` and adjust the values as needed:

```bash
cp .env-example .env
```

Key environment variables to configure:
- `JINAAI_EXT_PORT`: External port to access the Jina AI API (default: 8600)

### Usage

Start the service:

```bash
docker-compose up -d
```

Access the API at `http://localhost:8600` (or your configured port).

