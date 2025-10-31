# DarkSmart Deployment Guide

Complete guide to deploy your unified DarkSmart platform on Ubuntu VPS.

## Prerequisites

- Ubuntu 20.04+ VPS
- Node.js 18+ installed
- PostgreSQL installed
- Nginx installed
- Domain name pointing to your server (api.darksmart.pro)
- SSH access to server

## Step 1: Prepare the Server

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install Node.js 18
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt install -y nodejs

# Install PostgreSQL
sudo apt install -y postgresql postgresql-contrib

# Install Nginx
sudo apt install -y nginx

# Install Certbot for SSL
sudo apt install -y certbot python3-certbot-nginx

# Install PM2 for process management
sudo npm install -g pm2
```

## Step 2: Setup PostgreSQL Database

```bash
# Switch to postgres user
sudo -u postgres psql

# In PostgreSQL prompt:
CREATE DATABASE darksmart_db;
CREATE USER darksmart WITH PASSWORD '3imedelboosXX**';
GRANT ALL PRIVILEGES ON DATABASE darksmart_db TO darksmart;
\q

# Create database schema
sudo -u postgres psql -d darksmart_db < /var/www/api.darksmart.pro/schema.sql
```

## Step 3: Deploy Application Code

```bash
# Create directory structure
sudo mkdir -p /var/www/api.darksmart.pro
cd /var/www/api.darksmart.pro

# Upload/copy your application files
# Use scp, git, or rsync
# Example with git:
git clone <your-repo-url> .

# Install dependencies
npm install --production

# Add missing dependencies if needed
npm install jsonwebtoken bcryptjs express-validator
```

## Step 4: Create Production .env File

```bash
sudo nano /var/www/api.darksmart.pro/.env
```

Add the following (update values as needed):

```env
# Server
NODE_ENV=production
PORT=5050
BASE_URL=https://api.darksmart.pro
TRUST_PROXY=true

# Database
DATABASE_URL=postgresql://darksmart:3imedelboosXX**@localhost:5432/darksmart_db

# JWT Secret (CHANGE THIS!)
JWT_SECRET=a7f3d9e2c8b4f1a6e9d2c5b8f4a1e7d3c9b6f2a8e5d1c7b4f9a2e6d3c8b5f1a9e4d2c7b6f3a8e5d1c9b4f7a2e6d3c8b5f1a9e4d2c7b6f3a8e5d1

# Google OAuth (from Google Cloud Console)
GOOGLE_CLIENT_ID=1035771497728-c7d2klrleg3dq8vkgqubosvrbr6ourgl.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=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

# CORS
ALLOWED_ORIGINS=https://api.darksmart.pro

# PostgreSQL Pool
PG_POOL_MAX=10
PG_IDLE_TIMEOUT=30000
PG_CONN_TIMEOUT=5000
PG_MAX_RETRIES=5
```

```bash
# Secure the .env file
sudo chmod 600 /var/www/api.darksmart.pro/.env
sudo chown www-data:www-data /var/www/api.darksmart.pro/.env
```

## Step 5: Setup SSL Certificate

```bash
# Obtain SSL certificate from Let's Encrypt
sudo certbot certonly --nginx -d api.darksmart.pro

# Note the certificate paths:
# Certificate: /etc/letsencrypt/live/api.darksmart.pro/fullchain.pem
# Private Key: /etc/letsencrypt/live/api.darksmart.pro/privkey.pem

# Setup auto-renewal
sudo certbot renew --dry-run
```

## Step 6: Configure Nginx

```bash
# Create Nginx configuration
sudo nano /etc/nginx/sites-available/api.darksmart.pro
```

Paste the Nginx configuration (see `nginx_config` artifact).

```bash
# Enable site
sudo ln -s /etc/nginx/sites-available/api.darksmart.pro /etc/nginx/sites-enabled/

# Remove default site if present
sudo rm /etc/nginx/sites-enabled/default

# Test configuration
sudo nginx -t

# Restart Nginx
sudo systemctl restart nginx
sudo systemctl enable nginx
```

## Step 7: Start Application with PM2

```bash
cd /var/www/api.darksmart.pro

# Start with PM2
pm2 start server.js --name darksmart-api --node-args="--max-old-space-size=2048"

# Setup PM2 to start on boot
pm2 startup systemd
pm2 save

# Monitor logs
pm2 logs darksmart-api

# Check status
pm2 status
```

## Step 8: Configure Firewall

```bash
# Allow HTTP, HTTPS, and SSH
sudo ufw allow 22/tcp
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp

# Enable firewall
sudo ufw enable
```

## Step 9: Verify Deployment

```bash
# Check if service is running
curl -k https://api.darksmart.pro/health

# Should return: {"status":"ok","timestamp":"...","version":"1.0.0"}

# Test from your browser
https://api.darksmart.pro
```

## Step 10: Create Test User

```bash
# Option 1: Via API
curl -X POST https://api.darksmart.pro/auth/signup \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@darksmart.pro",
    "password": "testpass123",
    "name": "Test User"
  }'

# Option 2: Directly via PostgreSQL
sudo -u postgres psql -d darksmart_db
```

## Monitoring and Maintenance

### View Application Logs
```bash
pm2 logs darksmart-api
pm2 logs darksmart-api --lines 100
```

### View Nginx Logs
```bash
sudo tail -f /var/log/nginx/darksmart_access.log
sudo tail -f /var/log/nginx/darksmart_error.log
```

### Restart Application
```bash
pm2 restart darksmart-api
pm2 reload darksmart-api  # Zero-downtime reload
```

### Update Application
```bash
cd /var/www/api.darksmart.pro
git pull  # or upload new files
npm install --production
pm2 reload darksmart-api
```

### Database Backup
```bash
# Create backup
sudo -u postgres pg_dump darksmart_db > backup_$(date +%Y%m%d).sql

# Restore from backup
sudo -u postgres psql darksmart_db < backup_20231231.sql
```

### SSL Certificate Renewal
```bash
# Certificates auto-renew, but you can manually test:
sudo certbot renew --dry-run
```

## Google Home Integration

1. Go to Google Actions Console: https://console.actions.google.com
2. Create new project or select existing
3. Navigate to "Develop" > "Actions" > "Add your first action" > "Smart Home"
4. Fill in OAuth details:
   - Authorization URL: `https://api.darksmart.pro/oauth/authorize`
   - Token URL: `https://api.darksmart.pro/oauth/token`
   - Client ID: (from your .env)
   - Client Secret: (from your .env)
5. Set Fulfillment URL: `https://api.darksmart.pro/smarthome`
6. Save and test with Google Home app

## Troubleshooting

### Application won't start
```bash
pm2 logs darksmart-api --err
# Check for missing dependencies or environment variables
```

### Database connection errors
```bash
# Test database connection
sudo -u postgres psql -d darksmart_db -c "SELECT 1;"

# Check if PostgreSQL is running
sudo systemctl status postgresql
```

### Nginx 502 Bad Gateway
```bash
# Check if Node.js app is running
pm2 status

# Check Nginx error logs
sudo tail -f /var/log/nginx/darksmart_error.log
```

### SSL Certificate Issues
```bash
# Verify certificates exist
sudo ls -la /etc/letsencrypt/live/api.darksmart.pro/

# Test SSL
curl -vI https://api.darksmart.pro
```

## Security Checklist

- [x] Use HTTPS only
- [x] Strong JWT secret (minimum 64 characters)
- [x] Rate limiting enabled in Nginx
- [x] Database password secure
- [x] `.env` file has restricted permissions (600)
- [x] Firewall configured (UFW)
- [x] Regular security updates
- [x] HSTS headers enabled
- [x] No sensitive data in logs

## Performance Optimization

```bash
# Monitor resource usage
pm2 monit

# Increase Node.js memory if needed
pm2 delete darksmart-api
pm2 start server.js --name darksmart-api --node-args="--max-old-space-size=4096"

# Enable PostgreSQL query optimization
sudo -u postgres psql -d darksmart_db
VACUUM ANALYZE;
```

## Support

For issues, check:
- Application logs: `pm2 logs darksmart-api`
- Nginx logs: `/var/log/nginx/darksmart_*.log`
- PostgreSQL logs: `/var/log/postgresql/`
- System logs: `journalctl -xe`