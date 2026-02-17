# Caddy Configuration Guide

Caddy handles automatic SSL (via Let's Encrypt/ZeroSSL) and reverse proxying.

## Standard Caddyfile for Full-Stack

```caddy
{
    email your-email@example.com
}

your-domain.com {
    # Frontend SPA
    reverse_proxy frontend:80

    # API Requests
    handle_path /api/* {
        reverse_proxy backend:8080
    }

    # Admin Panel
    handle_path /admin/* {
        reverse_proxy admin:80
    }
}

# Optional: Redirect www to non-www
www.your-domain.com {
    redir https://your-domain.com{uri}
}
```

## SPA Routing in Nginx (Inside Frontend Container)

If using Nginx for the frontend build:

```nginx
server {
    listen 80;
    location / {
        root /usr/share/nginx/html;
        index index.html index.htm;
        try_files $uri $uri/ /index.html;
    }
}
```

## Security Headers

You can add these to the Caddyfile for better security:

```caddy
header {
    # disable FLoC tracking
    Permissions-Policy interest-cohort=()
    # HSTS
    Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
    # prevent clickjacking
    X-Frame-Options "SAMEORIGIN"
    # prevent sniffing
    X-Content-Type-Options "nosniff"
}
```
