# Типичные проблемы и их решения

## 1. Роутерный бот падает с `ModuleNotFoundError: No module named 'playwright'`
**Причина:** Playwright не установлен.
**Решение:**
```bash
pip install playwright
playwright install chromium

2. Основной бот не отправляет сообщения в Telegram

Причина: Недоступен прокси (Xray) или VPS.
Решение:

    Проверь статус Xray: sudo systemctl status xray

    Проверь порт: sudo ss -tulpn | grep 1080

    Если VPS лежит — дождись восстановления, либо переключи бота на BotGate.

3. Ошибка Connection reset by peer в логах бота

Причина: Прокси-сервер не отвечает.
Решение: Проверь соединение с VPS, перезапусти Xray.
4. Playwright не устанавливается из-за externally-managed-environment

Решение: Используй виртуальное окружение (см. docs/setup-router-bot.md).
5. Роутерный бот не видит устройства в сети

Причина: nmap не установлен.
Решение: sudo apt install nmap -y (на Debian) или sudo pacman -S nmap (на Arch)
