#!/bin/bash
BACKUP_DIR="/home/ros/backup"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
mkdir -p $BACKUP_DIR
tar -czf $BACKUP_DIR/configs_$TIMESTAMP.tar.gz /etc/pihole /etc/unbound /home/ros/network-bot 2>/dev/null
echo "Backup created: $BACKUP_DIR/configs_$TIMESTAMP.tar.gz"
