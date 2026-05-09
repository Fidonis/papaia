# Technitium DNS Service

This directory contains the configuration and deployment files for the Technitium DNS server.

## Overview

Technitium DNS Server is a powerful DNS server implementation that supports modern DNS standards and protocols. It provides features such as:

- Recursive DNS resolution
- Authoritative DNS hosting
- DNS-over-HTTPS (DoH) and DNS-over-TLS (DoT)
- DNS blocking and filtering capabilities
- Web-based administration interface


## Deployment

The Technitium DNS service is deployed using Docker Compose. To deploy the service:

```bash
docker-compose up -d
```

## Accessing the Admin Interface

Once deployed, the web-based admin interface can be accessed at:

- **URL**: `http://localhost:8120`
- **Default Username**: `admin`
- **Default Password**: `papaAIa2026`

It's recommended to change the default credentials after first login.

## Maintenance

### Backup

Important directories to backup:

- `config/` - Contains server configuration
- `data/` - Contains zone files and logs

### Monitoring

Logs can be viewed with:

```bash
docker-compose logs -f
```

## Troubleshooting

Common issues and solutions:

1. **Port conflicts**: Ensure ports 53 (DNS), 80 (HTTP), and 443 (HTTPS) are available
2. **Permission issues**: Check that the Docker user has appropriate permissions for mounted volumes
3. **Certificate errors**: Verify SSL certificate paths and validity for DoH/DoT functionality

## Additional Resources

- [Official Documentation](https://technitium.com/dns/)
- [GitHub Repository](https://github.com/TechnitiumSoftware/DnsServer)
- [Docker Hub Image](https://hub.docker.com/r/technitium/dns-server)