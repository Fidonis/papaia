#!/usr/bin/env bash

set -e

PROJECT_NAME="home-server"

# Auto-detect compose command
DC="docker compose"
command -v docker-compose >/dev/null && DC="docker-compose"

if [[ "$1" != "stop" && "$1" != "down" ]]; then
  echo "Usage: ./stop.sh [stop|down]"
  exit 1
fi

ACTION="$1"

echo "Stopping home-server services..."
$DC -p $PROJECT_NAME $ACTION

echo ""
echo "All stacks have been $ACTION."
