# Firecrawl Service

[Firecrawl](https://firecrawl.dev) is a service for crawling and converting web pages to markdown or structured data.  
Repo on GitHub: [firecrawl](https://github.com/firecrawl/firecrawl)

## Table of Contents
- [Overview](#overview)
- [Components](#components)
- [Prerequisites](#prerequisites)
- [Configuration](#configuration)
- [Usage](#usage)
- [API Endpoints](#api-endpoints)

## Overview

Firecrawl provides an easy-to-use API for:
- Crawling websites and converting them to clean markdown
- Extracting structured data from web pages using AI
- Taking screenshots of web pages
- Converting HTML to markdown

## Components

The Firecrawl service consists of multiple containers:
- `firecrawl`: Main API service
- `fc-playwright-service`: Browser automation service
- `fc-redis`: Redis cache/database
- `fc-rabbitmq`: Message queue
- `fc-nuq-postgres`: PostgreSQL database

## Prerequisites

- Docker and Docker Compose
- At least 8GB RAM allocated to Docker
- At least 4 CPU cores allocated to Docker

## Configuration

Before starting the service, copy the `.env-example` file to `.env` and adjust the values as needed:

```bash
cp .env-example .env
```

### Key Environment Variables

Below are some important environment variables you can configure in your `.env` file:

| Variable | Description | Default |
|----------|-------------|---------|
| `OPENAI_API_KEY` | Your OpenAI API key for LLM processing | - |
| `PORT` | External port to access the Firecrawl API | 3002 |
| `INTERNAL_PORT` | Internal port for the Firecrawl service | 3002 |
| `POSTGRES_USER` | PostgreSQL database user | postgres |
| `POSTGRES_PASSWORD` | PostgreSQL database password | postgres |
| `POSTGRES_DB` | PostgreSQL database name | postgres |
| `NUM_WORKERS_PER_QUEUE` | Number of workers per queue | 8 |
| `CRAWL_CONCURRENT_REQUESTS` | Concurrent requests during crawling | 10 |
| `BROWSER_POOL_SIZE` | Size of the browser pool | 5 |
| `LOGGING_LEVEL` | Logging level (debug, info, warn, error) | info |
| `BULL_AUTH_KEY` | Authentication key for the job queue dashboard | - |

For a complete list of environment variables, refer to the `.env-example` file.

## Usage

Start the service:

```bash
docker-compose up -d
```

Access the API at `http://localhost:3002` (or your configured port).

Stop the service:

```bash
docker-compose down
```

View logs:

```bash
docker-compose logs -f
```

## API Endpoints

### Scrape URL

Convert a single URL to markdown:

```bash
curl http://localhost:3002/v2/scrape \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com"}'
```

### Crawl Website

Crawl a website and extract multiple pages:

```bash
curl http://localhost:3002/v2/crawl \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com"}'
```



