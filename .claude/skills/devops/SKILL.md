---
name: devops
description: "Expert DevOps and deployment guidance for full-stack applications. Use this skill when deploying or managing applications using Docker, Docker Compose, Caddy, and VPS providers like DigitalOcean. Trigger this skill when the user asks for: (1) Setting up a VPS for deployment, (2) Dockerizing a Go/React application, (3) Configuring Caddy for SSL and reverse proxy, (4) Managing multi-container production environments, or (5) Establishing a deployment workflow."
---

# DevOps & Deployment

This skill provides expert guidance for deploying full-stack applications to VPS environments using Docker Compose and Caddy.

## Quick Start: Deployment Decision Tree

1. **New Server?**
   - Start with [VPS Setup Guide](references/vps-setup.md).
2. **Dockerizing the App?**
   - Use [Docker Patterns](references/docker-patterns.md) for Go, React, and Admin panels.
3. **Setting up SSL & Domains?**
   - Implement the [Caddy Configuration](references/caddy-config.md) for automatic SSL.
4. **Ready to Push?**
   - Follow the [Deployment Workflow](references/deployment-workflow.md).

## Core Capabilities

### 1. Production Dockerization

- Multi-stage builds for minimal image size.
- Environment variable management.
- Persistent volumes for databases and logs.
- Internal networking between services.

### 2. Edge Routing with Caddy

- Automatic HTTPS via Let's Encrypt.
- SPA (Single Page Application) routing.
- Path-based routing for API and Admin panels.
- Security header optimization.

### 3. VPS Management (DigitalOcean/Droplet)

- Firewall configuration (UFW).
- Docker engine installation.
- Security hardening (SSH, root access).

### 4. Deployment Workflows

- Zero-downtime deployment strategies.
- Database migration handling.
- Log monitoring and container health checks.

## Key References

- [VPS Setup](references/vps-setup.md): Initial server configuration.
- [Docker Patterns](references/docker-patterns.md): Multi-stage builds and Compose orchestration.
- [Caddy Config](references/caddy-config.md): Caddyfile examples and SPA routing.
- [Deployment Workflow](references/deployment-workflow.md): Step-by-step production push.
