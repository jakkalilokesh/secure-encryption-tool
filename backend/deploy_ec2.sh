#!/bin/bash

# Secure Encryption Tool - EC2 Deployment Script
# Usage: ./deploy_ec2.sh

set -e

APP_DIR="/home/ubuntu/secure-encryption-tool"
BACKEND_DIR="$APP_DIR/backend"
VENV_DIR="$BACKEND_DIR/venv"

echo ">>> Updating system..."
sudo apt-get update && sudo apt-get upgrade -y

echo ">>> Installing dependencies..."
sudo apt-get install -y python3-pip python3-venv nginx git

echo ">>> Setting up application directory..."
if [ ! -d "$APP_DIR" ]; then
    echo "Cloning repository..."
    # You might need to change this URL if using a private repo or different user
    git clone https://github.com/JAKKALI-LOKESH-g13-cs-1/secure-encryption-tool.git $APP_DIR
else
    echo "Pulling latest changes..."
    cd $APP_DIR
    git pull
fi

echo ">>> Setting up Python environment..."
cd $BACKEND_DIR
if [ ! -d "$VENV_DIR" ]; then
    python3 -m venv $VENV_DIR
fi

source $VENV_DIR/bin/activate
pip install -r requirements.txt

echo ">>> Configuring Systemd Service..."
SERVICE_FILE="/etc/systemd/system/secure-backend.service"

sudo bash -c "cat > $SERVICE_FILE" <<EOL
[Unit]
Description=Gunicorn instance to serve Secure Encryption Tool Backend
After=network.target

[Service]
User=ubuntu
Group=www-data
WorkingDirectory=$BACKEND_DIR
Environment="PATH=$VENV_DIR/bin"
ExecStart=$VENV_DIR/bin/gunicorn -w 4 -k uvicorn.workers.UvicornWorker main:app --bind 0.0.0.0:8000

[Install]
WantedBy=multi-user.target
EOL

sudo systemctl daemon-reload
sudo systemctl enable secure-backend
sudo systemctl restart secure-backend

echo ">>> Configuring Nginx..."
NGINX_CONF="/etc/nginx/sites-available/secure-backend"

sudo bash -c "cat > $NGINX_CONF" <<EOL
server {
    listen 80;
    server_name _;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}
EOL

# Enable the site and remove default if it exists
if [ -f /etc/nginx/sites-enabled/default ]; then
    sudo rm /etc/nginx/sites-enabled/default
fi

if [ ! -f /etc/nginx/sites-enabled/secure-backend ]; then
    sudo ln -s $NGINX_CONF /etc/nginx/sites-enabled/
fi

sudo nginx -t
sudo systemctl restart nginx

echo ">>> Deployment Complete!"
echo "Your backend should be accessible at http://<YOUR_EC2_PUBLIC_IP>/"
