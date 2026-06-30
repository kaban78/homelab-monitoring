#!/bin/bash
echo "=== Проверка сервисов Raspberry Pi ==="
services=("pihole-FTL" "unbound" "wg-quick@wg0" "network-bot" "xray" "ssh" "NetworkManager")
for svc in "${services[@]}"; do
    if systemctl is-active --quiet "$svc"; then
        echo "✅ $svc: active"
    else
        echo "❌ $svc: inactive"
    fi
done
echo "=== Проверка интернет-соединения ==="
ping -c 2 8.8.8.8 &>/dev/null && echo "✅ Интернет есть" || echo "❌ Интернет отсутствует"
