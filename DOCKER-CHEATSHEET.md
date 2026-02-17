# Docker Compose Cheatsheet for Kamino

Quick reference for common Docker Compose operations.

## Quick Start

```bash
# Start everything
docker-compose up -d

# Stop everything
docker-compose down

# View status
docker-compose ps

# View logs
docker-compose logs -f
```

## Service Management

| Command | What it does |
|---------|-------------|
| `docker-compose up -d` | Start all services in background |
| `docker-compose down` | Stop and remove containers (keeps volumes) |
| `docker-compose down -v` | Stop and remove everything (deletes data) |
| `docker-compose stop` | Stop services (keeps containers) |
| `docker-compose start` | Start stopped services |
| `docker-compose restart app` | Restart specific service |
| `docker-compose ps` | Show all services and status |

## Viewing Logs

```bash
# All logs
docker-compose logs

# Specific service
docker-compose logs app
docker-compose logs postgres

# Follow logs (real-time)
docker-compose logs -f app

# Last N lines
docker-compose logs --tail=50 app

# With timestamps
docker-compose logs --timestamps

# Since specific time
docker-compose logs --since 5m
```

## Database Access

```bash
# Connect to PostgreSQL
docker-compose exec postgres psql -U postgres -d kamino

# Run SQL query directly
docker-compose exec -T postgres psql -U postgres -d kamino \
  -c "SELECT * FROM users;"

# Backup database
docker-compose exec -T postgres pg_dump -U postgres kamino > backup.sql

# Restore database
docker-compose exec -T postgres psql -U postgres kamino < backup.sql

# Run migrations
./migrate.sh
```

## Debugging

```bash
# Shell in app container
docker-compose exec app sh

# Shell in postgres container
docker-compose exec postgres sh

# Run app directly
docker-compose exec app ./kamino

# Health check
curl http://localhost:8080/health

# Database connectivity test
docker-compose exec app nc -zv postgres 5432
```

## API Testing

```bash
# Health check
curl http://localhost:8080/health

# Create user
curl -X POST "http://localhost:8080/users" \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","name":"Test","password":"pass","role":"user"}'

# List users
curl http://localhost:8080/users

# Get specific user
curl http://localhost:8080/users/UUID_HERE

# Update user
curl -X PUT "http://localhost:8080/users/UUID_HERE" \
  -H "Content-Type: application/json" \
  -d '{"name":"Updated Name"}'

# Delete user
curl -X DELETE "http://localhost:8080/users/UUID_HERE"
```

## Building & Deployment

```bash
# Build images
docker-compose build

# Build without cache
docker-compose build --no-cache

# Build and start
docker-compose up -d --build

# Build specific service
docker-compose build app

# Show image info
docker image inspect kamino-app
docker image inspect kamino-app | jq '.[0].Config'
```

## Resource Management

```bash
# View resource usage
docker stats kamino-app kamino-postgres

# View image size
docker images | grep kamino

# View volumes
docker volume ls | grep kamino

# Remove unused resources
docker system prune

# Remove specific volume
docker volume rm kamino-postgres-data
```

## Configuration

```bash
# View docker-compose configuration
docker-compose config

# Validate syntax
docker-compose config --quiet

# Environment variables
cat .env

# Override variables
DB_PASSWORD=newpass docker-compose up -d
```

## Troubleshooting

```bash
# Check service logs
docker-compose logs postgres
docker-compose logs app

# Test port availability
lsof -i :5432   # PostgreSQL
lsof -i :8080   # API

# Check network
docker network ls | grep kamino
docker network inspect kamino-network

# Test connectivity
docker-compose exec app ping postgres

# Database test
docker-compose exec postgres pg_isready -U postgres
```

## Common Scenarios

### Rebuild After Code Changes

```bash
docker-compose up -d --build app
```

### Reset Database and Start Fresh

```bash
docker-compose down -v
docker-compose up -d
./migrate.sh
```

### Check What's Consuming Disk

```bash
docker system df
```

### View Detailed Service Info

```bash
docker inspect kamino-app
docker inspect kamino-postgres
```

### Port in Use Error

```bash
# Kill process using port
lsof -i :8080
kill -9 PID

# Or change port in .env
DB_PORT=5433
PORT=8081
```

### See All Docker Commands

```bash
docker-compose --help
```

### Connect to Postgres from Host

```bash
# If psql installed locally
PGPASSWORD=testpasswordkamino psql -h localhost -U postgres -d kamino

# Get connection string
echo "postgresql://postgres:testpasswordkamino@localhost:5432/kamino"
```

## Environment Variables

```bash
# Copy template
cp .env.example .env

# Edit configuration
nano .env  # or your editor

# Key variables:
DB_HOST=postgres          # For Docker
DB_HOST=localhost         # For local development
DB_PASSWORD=your_password # CHANGE THIS
ENV=development
LOG_LEVEL=info
PORT=8080
```

## Monitoring

```bash
# Continuous health check
watch "curl -s http://localhost:8080/health | jq ."

# Monitor logs in real-time
docker-compose logs -f --all

# Check container status changes
watch docker-compose ps

# Database connections
docker-compose exec -T postgres psql -U postgres -d kamino \
  -c "SELECT datname, numbackends FROM pg_stat_database WHERE datname='kamino';"
```

## Production Checklist

- [ ] Update `.env` with secure passwords
- [ ] Set `ENV=production`
- [ ] Set `LOG_LEVEL=warn`
- [ ] Use `DB_SSLMODE=require`
- [ ] Increase `DB_MAX_CONNS` if high traffic
- [ ] Backup database regularly
- [ ] Monitor logs and health checks
- [ ] Set up automated backups
- [ ] Configure reverse proxy (Nginx/Caddy)
- [ ] Use Docker secrets for sensitive data

## Docker File Locations

- **Dockerfile**: `/Dockerfile` - Multi-stage build
- **Docker Compose**: `/docker-compose.yml` - Full stack config
- **Ignore file**: `/.dockerignore` - Build optimization
- **Migrations**: `/migrations/*.sql` - Database schemas
- **Scripts**: `/migrate.sh` - Migration helper
- **Docs**: `/DOCKER.md` - Detailed documentation

## Quick Ports Reference

| Service | Port | URL |
|---------|------|-----|
| API | 8080 | http://localhost:8080 |
| PostgreSQL | 5432 | postgres://localhost:5432 |
| Health Check | 8080 | http://localhost:8080/health |

## Getting Help

```bash
# Docker Compose help
docker-compose --help
docker-compose COMMAND --help

# View specific container logs
docker-compose logs app -f --tail=100

# Inspect container
docker inspect kamino-app | jq .

# Check docker installation
docker version
docker-compose version
```

---

For detailed documentation, see [DOCKER.md](./DOCKER.md)
