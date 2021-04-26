#!/usr/bin/env bash
sudo apt-get install -y nginx
sudo systemctl enable nginx
sudo systemctl start nginx
sudo mv index.html /var/www/html/