# Deployment Workflow

This guide outlines the steps to deploy the application to production.

## 1. Local Preparation

1. Ensure all environment variables are defined in a `.env.prod` file (but NOT committed).
2. Verify Dockerfiles and Caddyfile are correct.

## 2. Server Setup (First Time Only)

Follow the [VPS Setup Guide](vps-setup.md).

## 3. Transferring Files

You can use `rsync` or `scp` to move configuration files:

```bash
rsync -avz --exclude 'node_modules' --exclude '.git' . root@your_ip:/opt/app
```

## 4. Building and Running (On VPS)

```bash
cd /opt/app
docker compose -f docker-compose.prod.yml up --build -d
```

## 5. Database Migrations

Run migrations within the backend container:

```bash
docker compose exec backend ./main migrate
# Or if using goose separately:
docker compose exec backend ./goose up
```

## 6. Verification

1. Check container status: `docker compose ps`
2. Check logs: `docker compose logs -f`
3. Verify SSL: Visit `https://your-domain.com`

## 7. Continuous Deployment (Simple Script)

Create a `deploy.sh` on the server:

```bash
#!/bin/bash
git pull origin main
docker compose up --build -d
docker compose exec backend ./migrate # if applicable
```
