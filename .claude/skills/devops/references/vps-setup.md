# VPS Setup Guide (DigitalOcean Droplet)

This guide provides a standardized approach to setting up a Ubuntu-based VPS for hosting full-stack applications.

## 1. Initial Access & Updates

```bash
ssh root@your_ip
apt update && apt upgrade -y
```

## 2. Docker & Docker Compose Installation

Install Docker using the official repository:

```bash
# Add Docker's official GPG key:
sudo apt-get update
sudo apt-get install ca-certificates curl
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc

# Add the repository to Apt sources:
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu \
  $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update

# Install Docker
sudo apt-get install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
```

## 3. Firewall (UFW) Configuration

Standard web ports:

```bash
ufw allow ssh
ufw allow http
ufw allow https
ufw enable
```

## 4. SSH Hardening (Recommended)

Edit `/etc/ssh/sshd_config`:

- `PermitRootLogin prohibit-password`
- `PasswordAuthentication no`
  Then restart ssh: `systemctl restart ssh`

## 5. Deployment Directory

Create a standard location for the application:

```bash
mkdir -p /opt/app
cd /opt/app
```
