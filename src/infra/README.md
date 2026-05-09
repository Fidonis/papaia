# Infrastructure

This directory contains the infrastructure configuration for the project.

## Nginx Proxy Manager

The project uses Nginx Proxy Manager (NPM) to handle reverse proxying and SSL termination.

### Services

- **Nginx Proxy Manager**: Running on port 80 (HTTP), 443 (HTTPS), and 8100 (Admin UI)

### Configuration

The service is configured using Docker Compose with the following key settings:

- Image: `jc21/nginx-proxy-manager:latest`
- Container name: `nginx-proxy-manager`
- Restart policy: `unless-stopped`
- Ports:
  - `80:80` (HTTP)
  - `443:443` (HTTPS)
  - `${NPM_ADMIN_EXT_PORT:-8100}:81` (Admin UI)

### Volumes

- `npm-data`: Stores NPM data
- `npm-letsencrypt`: Stores Let's Encrypt certificates

### Networks

- Uses a default network defined by `${DOCKER_NETWORK}` environment variable

### Environment Variables

To configure the service, create a `.env` file in the `nginx` directory based on the `.env.example` template.

### Usage

1. Navigate to the `nginx` directory
2. Create a `.env` file with your configuration
3. Run `docker-compose up -d` to start the services
4. Access the admin interface at `http://localhost:8100` (or your configured port)