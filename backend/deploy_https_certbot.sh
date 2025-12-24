#!/bin/bash

# Enable HTTPS (Real Certificate)
# ONLY run this if you have specific domain name pointed to your IP.
# Usage: ./deploy_https_certbot.sh yourdomain.com

DOMAIN=$1

if [ -z "$DOMAIN" ]; then
    echo "Usage: ./deploy_https_certbot.sh <YOUR_DOMAIN_NAME>"
    exit 1
fi

set -e

echo ">>> Installing Certbot..."
sudo apt-get install -y certbot python3-certbot-nginx

echo ">>> configuring Nginx for Domain..."
# We need a basic config first so Certbot can verify the domain
sudo bash -c "cat > /etc/nginx/sites-available/secure-backend" <<EOL
server {
    listen 80;
    server_name $DOMAIN;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
    }
}
EOL
sudo systemctl restart nginx

echo ">>> Obtaining Certificate..."
sudo certbot --nginx -d $DOMAIN --non-interactive --agree-tos -m admin@$DOMAIN

echo ">>> HTTPS Enabled!"
