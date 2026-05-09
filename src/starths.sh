#!/usr/bin/env bash

set -e  # exit on any error

# Auto-detect compose command
DC="docker compose"
command -v docker-compose >/dev/null && DC="docker-compose"

PROJECT_NAME="home-server"
DOCKER_NETWORK="hs-net"
INFRA_SERVICES_DIR="./infra"
AI_SERVICES_DIR="./ai"
COMMON_SERVICES_DIR="./services"

# Check if docker network exists, if not create it
if ! docker network inspect "$DOCKER_NETWORK" >/dev/null 2>&1; then
    echo "Network '$DOCKER_NETWORK' does not exist - creating..."
    docker network create -d bridge "$DOCKER_NETWORK"
else
    echo "Network '$DOCKER_NETWORK' already exists."
fi

# Infrastructrure services
$DC --env-file $INFRA_SERVICES_DIR/nginx/.env --env-file ./.env -p "$PROJECT_NAME" -f $INFRA_SERVICES_DIR/nginx/docker-compose.yml up -d
$DC --env-file $INFRA_SERVICES_DIR/technitium/.env --env-file ./.env -p "$PROJECT_NAME" -f $INFRA_SERVICES_DIR/technitium/docker-compose.yml up -d
$DC --env-file $INFRA_SERVICES_DIR/keycloak/.env --env-file ./.env -p "$PROJECT_NAME" -f $INFRA_SERVICES_DIR/keycloak/docker-compose.yml up -d

# Services
$DC --env-file $COMMON_SERVICES_DIR/searxng/.env --env-file ./.env -p "$PROJECT_NAME" -f $COMMON_SERVICES_DIR/searxng/docker-compose.yml up -d
$DC --env-file $COMMON_SERVICES_DIR/firecrawl/.env --env-file ./.env -p "$PROJECT_NAME" -f $COMMON_SERVICES_DIR/firecrawl/docker-compose.yml up -d
$DC --env-file $COMMON_SERVICES_DIR/jinaai/.env --env-file ./.env -p "$PROJECT_NAME" -f $COMMON_SERVICES_DIR/jinaai/docker-compose.yml up -d
$DC --env-file $COMMON_SERVICES_DIR/home-assistant/.env --env-file ./.env -p "$PROJECT_NAME" -f $COMMON_SERVICES_DIR/home-assistant/docker-compose.yml up -d
$DC --env-file $COMMON_SERVICES_DIR/paperless/.env --env-file ./.env -p "$PROJECT_NAME" -f $COMMON_SERVICES_DIR/paperless/docker-compose.yml up -d
$DC --env-file $COMMON_SERVICES_DIR/homepage/.env --env-file ./.env -p "$PROJECT_NAME" -f $COMMON_SERVICES_DIR/homepage/docker-compose.yml up -d

# AI stuff
$DC --env-file $AI_SERVICES_DIR/mcp-paperless/.env --env-file ./.env -p "$PROJECT_NAME" -f $AI_SERVICES_DIR/mcp-paperless/docker-compose.yml up -d
$DC --env-file $AI_SERVICES_DIR/localai/.env --env-file ./.env -p "$PROJECT_NAME" -f $AI_SERVICES_DIR/localai/docker-compose.yml up -d
$DC --env-file $AI_SERVICES_DIR/litellm/.env --env-file ./.env -p "$PROJECT_NAME" -f $AI_SERVICES_DIR/litellm/docker-compose.yml up -d
$DC --env-file $AI_SERVICES_DIR/doc-rag/.env --env-file ./.env -p "$PROJECT_NAME" -f $AI_SERVICES_DIR/doc-rag/docker-compose.yml up -d
$DC --env-file $AI_SERVICES_DIR/librechat/.env --env-file ./.env -p "$PROJECT_NAME" -f $AI_SERVICES_DIR/librechat/docker-compose.yml up -d
$DC --env-file $AI_SERVICES_DIR/n8n/.env --env-file ./.env -p "$PROJECT_NAME" -f $AI_SERVICES_DIR/n8n/docker-compose.yml up -d
