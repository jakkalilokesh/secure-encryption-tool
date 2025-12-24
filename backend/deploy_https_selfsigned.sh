#!/bin/bash

# Enable HTTPS (Self-Signed)
# Use this if you only have an IP address and no domain name.

set -e

echo ">>> Generating Self-Signed SSL Certificate..."
sudo mkdir -p /etc/nginx/ssl
sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /etc/nginx/ssl/selfsigned.key \
    -out /etc/nginx/ssl/selfsigned.crt \
    -subj "/C=US/ST=State/L=City/O=Organization/CN=100.27.49.220"

echo ">>> Configuring Nginx for HTTPS..."
NGINX_CONF="/etc/nginx/sites-available/secure-backend"

sudo bash -c "cat > $NGINX_CONF" <<EOL
server {
    listen 80;
    server_name _;
    return 301 https://\$host\$request_uri;
}

server {
    listen 443 ssl;
    server_name _;

    ssl_certificate /etc/nginx/ssl/selfsigned.crt;
    ssl_certificate_key /etc/nginx/ssl/selfsigned.key;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
    }
}
EOL

echo ">>> Restarting Nginx..."
sudo nginx -t
sudo systemctl restart nginx

echo ">>> HTTPS Enabled (Self-Signed)!"
echo "IMPORTANT: When you visit the site, you will see a 'Not Secure' warning."
echo "You must click 'Advanced' -> 'Proceed to IP' to accept the certificate."
