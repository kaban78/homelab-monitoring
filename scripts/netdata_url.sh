#!/bin/bash
IP=$(hostname -I | awk '{print $1}')
echo "Netdata dashboard: http://$IP:19999"
