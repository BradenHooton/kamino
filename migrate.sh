#!/bin/bash
set -e

# Load environment variables from .env if it exists
if [ -f .env ]; then
    export $(grep -v '^#' .env | xargs)
fi

# Database configuration
DB_HOST="${DB_HOST:-localhost}"
DB_PORT="${DB_PORT:-5432}"
DB_USER="${DB_USER:-postgres}"
DB_PASSWORD="${DB_PASSWORD:-testpasswordkamino}"
DB_NAME="${DB_NAME:-kamino}"
DB_SSLMODE="${DB_SSLMODE:-disable}"

echo "🚀 Running database migrations..."
echo "Database: ${DB_HOST}:${DB_PORT}/${DB_NAME}"

# Check if running in docker-compose environment
if [ -n "$DOCKER_HOST" ] || command -v docker-compose &> /dev/null; then
    # Running in or with Docker
    if docker-compose ps 2>/dev/null | grep -q kamino-postgres; then
        echo "Using docker-compose exec to run migrations..."

        # Extract only the UP portion of Goose migrations and run them
        for migration_file in migrations/*.sql; do
            if [ -f "$migration_file" ]; then
                echo "Applying migration: $(basename $migration_file)"
                # Extract the section between "+goose Up" and "+goose Down"
                sed -n '/-- +goose Up/,/-- +goose Down/p' "$migration_file" | \
                    sed '1d;$d' | \
                    docker-compose exec -T postgres psql -U "$DB_USER" -d "$DB_NAME" >/dev/null 2>&1
            fi
        done
        echo "✅ Migrations completed successfully"
        exit 0
    fi
fi

# Fallback: Try to use psql directly
if command -v psql &> /dev/null; then
    echo "Using psql CLI..."
    PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" \
        -c "$(sed -n '/-- +goose Up/,/-- +goose Down/p' migrations/*.sql | sed '1d;$d')"
    echo "✅ Migrations completed successfully"
    exit 0
fi

# If we get here, we couldn't run migrations
echo "❌ Error: Could not run migrations"
echo "Options:"
echo "  1. Run: docker-compose exec -T postgres psql -U postgres -d kamino < <(sed -n '/-- +goose Up/,/-- +goose Down/p' migrations/*.sql | sed '1d;$d')"
echo "  2. Install psql locally and set DB_HOST=localhost"
echo "  3. Use the provided SQL directly in your database client"
exit 1
