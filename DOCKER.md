# Docker Setup for Kamino

This guide explains the containerized setup for the Kamino backend API.

## Overview

The Docker Compose configuration provides:

- **PostgreSQL 15**: Persistent database with health checks
- **Kamino API**: Multi-stage built Go application running on port 8080
- **Networking**: Custom bridge network for inter-service communication
- **Volumes**: Data persistence across container restarts

```
┌──────────────────────────────────────┐
│         docker-compose               │
├──────────────────────────────────────┤
│  postgres:15-alpine  ← kamino-postgres│  Port 5432
│  (Data: kamino-postgres-data/)       │
├──────────────────────────────────────┤
│  kamino-app (from Dockerfile)        │  Port 8080
│  - Health check: GET /health         │
│  - Graceful shutdown: 30s            │
└──────────────────────────────────────┘
```

## Quick Start

### 1. Prerequisites

- Docker & Docker Compose installed
- `.env` file configured (see Configuration section)

### 2. Start Services

```bash
# Build and start all services in the background
docker-compose up -d

# View real-time logs
docker-compose logs -f

# Check service health
docker-compose ps
```

### 3. Verify Setup

```bash
# Health check endpoint
curl http://localhost:8080/health

# Expected response:
# {"status":"healthy","database":"up"}
```

### 4. Stop Services

```bash
# Stop (keeps data)
docker-compose stop

# Stop and remove containers (keeps volumes)
docker-compose down

# Stop and remove everything (deletes data)
docker-compose down -v
```

## Configuration

### Environment Variables

Copy `.env.example` to `.env` and customize:

```bash
cp .env.example .env
```

**Key variables for Docker:**

```env
# Database
DB_HOST=postgres          # Service name within Docker network
DB_PORT=5432
DB_USER=postgres
DB_PASSWORD=your_password # CHANGE THIS!
DB_NAME=kamino

# Connection Pool
DB_MAX_CONNS=25
DB_MIN_CONNS=5

# Server
PORT=8080
ENV=development
LOG_LEVEL=info
```

**For local development (outside Docker):**

```env
DB_HOST=localhost         # Localhost on host machine
```

### .dockerignore

The `.dockerignore` file optimizes Docker builds by excluding unnecessary files:
- Test files, git metadata, IDE configs
- Results in faster builds and smaller build context

## Database Migrations

### Automatic Migrations on First Run

Migrations are SQL files in the `migrations/` directory. They use Goose format with `-- +goose Up` and `-- +goose Down` markers.

### Manual Migration Running

**Option 1: Using the migration script**

```bash
chmod +x migrate.sh
./migrate.sh
```

**Option 2: Using docker-compose exec**

```bash
docker-compose exec -T postgres psql -U postgres -d kamino \
  < <(sed -n '/-- +goose Up/,/-- +goose Down/p' migrations/001_create_users.sql | sed '1d;$d')
```

**Option 3: Direct psql access**

```bash
docker-compose exec postgres psql -U postgres -d kamino
```

Then inside psql:

```sql
-- Create users table
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) NOT NULL UNIQUE,
    password_hash TEXT,
    ...
);
```

## Development Workflow

### 1. Making Code Changes

```bash
# Your code in the host machine (linked via volumes implicitly through build)
# Edit src files, then rebuild:

docker-compose up -d --build app
```

### 2. Checking Logs

```bash
# View all logs
docker-compose logs

# View specific service
docker-compose logs app
docker-compose logs postgres

# Follow logs in real-time (last 50 lines)
docker-compose logs -f --tail=50 app

# View logs with timestamps
docker-compose logs --timestamps
```

### 3. Database Inspection

```bash
# Connect to postgres container
docker-compose exec postgres psql -U postgres -d kamino

# Common psql commands:
# \dt           - List tables
# \d users      - Describe table
# SELECT * FROM users;  - Query
# \q            - Exit
```

### 4. Testing API Endpoints

```bash
# Create user
curl -X POST "http://localhost:8080/users" \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","name":"Test","password":"pass","role":"user"}'

# List users
curl http://localhost:8080/users

# Get user by ID
curl http://localhost:8080/users/{id}

# Update user
curl -X PUT "http://localhost:8080/users/{id}" \
  -H "Content-Type: application/json" \
  -d '{"name":"Updated Name"}'

# Delete user
curl -X DELETE "http://localhost:8080/users/{id}"
```

## Production Deployment

### Environment Variables for Production

```env
DB_PASSWORD=very_strong_password_change_me
DB_SSLMODE=require
ENV=production
LOG_LEVEL=warn
DB_MAX_CONNS=100
```

### Health Checks

The containers include health checks that automatically restart failed services:

```yaml
healthcheck:
  test: ["CMD", "wget", "--no-verbose", "--tries=1", "--spider", "http://localhost:8080/health"]
  interval: 30s
  timeout: 10s
  retries: 3
  start_period: 40s
```

### Graceful Shutdown

The app waits up to 30 seconds for requests to complete before exiting:

```yaml
stop_grace_period: 30s
```

## Troubleshooting

### Services Won't Start

```bash
# Check logs
docker-compose logs

# Verify Docker is running
docker ps

# Check port availability
lsof -i :5432  # PostgreSQL port
lsof -i :8080  # App port

# Rebuild images
docker-compose build --no-cache
```

### Database Connection Issues

```bash
# Test postgres connectivity from app container
docker-compose exec app nc -zv postgres 5432

# Check if postgres is healthy
docker-compose exec postgres pg_isready -U postgres

# Inspect postgres logs
docker-compose logs postgres
```

### Port Conflicts

If port 5432 or 8080 are in use, modify `.env`:

```env
DB_PORT=5433        # PostgreSQL on different port
PORT=8081           # App on different port
```

Then update docker-compose references if needed, or ports are automatically updated via env variables.

### Data Issues

```bash
# Backup data before deleting
docker-compose exec postgres pg_dump -U postgres kamino > backup.sql

# Remove all data and start fresh
docker-compose down -v

# Restore data
docker-compose up -d
docker-compose exec -T postgres psql -U postgres kamino < backup.sql
```

### Container Health

```bash
# Check health status
docker-compose ps

# Restart unhealthy container
docker-compose restart app

# View detailed container info
docker inspect kamino-app

# View resource usage
docker stats kamino-app kamino-postgres
```

## Image Optimization

The Dockerfile uses multi-stage builds for optimal image size:

**Stage 1 (Builder):**
- golang:1.24.5-alpine (~900MB)
- Compiles Go binary
- Discarded after build

**Stage 2 (Runtime):**
- alpine:latest (~7MB)
- Only the compiled binary (~10-15MB)
- Non-root user for security

**Result:**
- 95%+ size reduction vs single-stage
- Final image: ~15-20MB
- Minimal attack surface

## Security Features

✅ **Non-root user** - App runs as user `kamino` (UID 1000)
✅ **Minimal image** - Only binary and runtime dependencies
✅ **No build tools** - Builder stage discarded
✅ **Static binary** - CGO_ENABLED=0 (no C dependencies)
✅ **Environment variables** - No secrets in images
✅ **Health checks** - Automatic restart on failure
✅ **Network isolation** - Custom bridge network
✅ **Read-only migrations** - `:ro` mount flags

## Common Commands Reference

```bash
# Service Management
docker-compose up -d                   # Start all services
docker-compose down                    # Stop and remove containers
docker-compose stop                    # Stop (keep containers)
docker-compose start                   # Start stopped containers
docker-compose restart app             # Restart specific service

# Viewing Status
docker-compose ps                      # Show all services
docker-compose logs                    # View logs
docker-compose logs -f app             # Follow app logs
docker-compose logs --tail=50 app      # Last 50 lines
docker stats                           # Resource usage

# Database
docker-compose exec postgres psql -U postgres -d kamino  # Connect
./migrate.sh                           # Run migrations
docker-compose exec -T postgres pg_dump -U postgres kamino > backup.sql

# Building
docker-compose build                   # Build all services
docker-compose build --no-cache app    # Rebuild without cache
docker-compose up -d --build           # Build and start

# Debugging
docker-compose exec app sh             # Shell in app container
docker-compose exec app ./kamino       # Run app directly
docker-compose run --rm app sh         # Temporary container

# Cleanup
docker-compose down -v                 # Remove containers and volumes
docker system prune                    # Remove unused Docker resources
docker image rm kamino-app:latest      # Remove image
```

## Networking

Services communicate via the custom `kamino-network` bridge:

- **postgres**: Accessible at `postgres:5432` from other containers
- **app**: Accessible at `kamino-app:8080` from other containers
- **host**: Services accessible at `localhost:5432` and `localhost:8080`

## Performance Tuning

### Connection Pool

```env
DB_MAX_CONNS=50          # Increase for high traffic
DB_MIN_CONNS=10
DB_MAX_CONN_LIFETIME=10m # Connection lifetime
DB_MAX_CONN_IDLE_TIME=5m # Idle timeout
```

### PostgreSQL

```yaml
services:
  postgres:
    environment:
      POSTGRES_INITDB_ARGS: "--encoding=UTF-8 --shared_buffers=256MB"
```

## Monitoring

### Health Status

```bash
# Direct health check
curl http://localhost:8080/health

# Continuous monitoring
watch curl http://localhost:8080/health

# With database check
curl http://localhost:8080/health | jq .database
```

### Logs Analysis

```bash
# Errors only
docker-compose logs | grep -i error

# JSON logs (structured)
docker-compose logs app | jq .

# Specific timeframe
docker-compose logs --since 5m --until 1m
```

## Scaling

For local development, single instances are fine. For production:

```bash
# Scale app service (requires load balancer)
docker-compose up -d --scale app=3

# This requires a reverse proxy (Nginx/Caddy) to distribute traffic
```

Note: Scaling requires additional setup with a reverse proxy and load balancer.

## CI/CD Integration

The Docker Compose setup is suitable for:

- **Local Development**: Full stack with one command
- **Integration Tests**: Reliable, isolated environment
- **Staging**: Mirrors production closely
- **Production**: Adapt for Docker Swarm or Kubernetes

## Additional Resources

- [Docker Documentation](https://docs.docker.com/)
- [Docker Compose Specification](https://github.com/compose-spec/compose-spec)
- [PostgreSQL in Docker](https://hub.docker.com/_/postgres)
- [Go Docker Best Practices](https://www.capitalone.com/tech/cloud-container-security/)

## Getting Help

If you encounter issues:

1. Check logs: `docker-compose logs`
2. Verify ports: `lsof -i :5432` and `lsof -i :8080`
3. Test connectivity: `docker-compose exec postgres psql -U postgres -d kamino`
4. Review `.env` configuration
5. Rebuild images: `docker-compose build --no-cache`
