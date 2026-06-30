#!/usr/bin/env python3
import os
import asyncio
import json
import subprocess
import re
from playwright.async_api import async_playwright

# ==================== ПЕРЕМЕННЫЕ ОКРУЖЕНИЯ ====================
TELEGRAM_TOKEN = os.getenv("TELEGRAM_TOKEN")
CHAT_ID = os.getenv("CHAT_ID")
ROUTER_IP = os.getenv("ROUTER_IP", "192.168.0.1")
ROUTER_PASSWORD = os.getenv("ROUTER_PASSWORD")

if not TELEGRAM_TOKEN or not CHAT_ID or not ROUTER_PASSWORD:
    print("❌ Ошибка: TELEGRAM_TOKEN, CHAT_ID и ROUTER_PASSWORD должны быть заданы в .env")
    exit(1)

HISTORY_FILE = "/tmp/router_devices_history.json"

def scan_local_network():
    print("🔍 Запуск nmap сканирования локальной сети...")
    current_ips = set()
    devices_display = []
    try:
        cmd = f"nmap -sn {ROUTER_IP}/24"
        result = subprocess.check_output(cmd, shell=True, text=True)
        ips = re.findall(r"Nmap scan report for (?:[^\s]+\s+\()?([\d.]+)\)?", result)
        for ip in ips:
            if ip != ROUTER_IP and ip != "192.168.0.0":
                current_ips.add(ip)
                devices_display.append(f"  ├ {ip}")
    except Exception as e:
        print(f"❌ Ошибка при выполнении nmap: {e}")
        return "", "", 0

    alert_msg = ""
    old_ips = set()
    if os.path.exists(HISTORY_FILE):
        try:
            with open(HISTORY_FILE, "r") as f:
                old_ips = set(json.load(f))
        except:
            pass

    new_devices = current_ips - old_ips
    disconnected_devices = old_ips - current_ips

    if new_devices or disconnected_devices:
        alert_msg = "⚠️ ОБНАРУЖЕНЫ ИЗМЕНЕНИЯ В СЕТИ:\n"
        for ip in new_devices:
            alert_msg += f"  ➕ ПОДКЛЮЧИЛОСЬ НОВОЕ УСТРОЙСТВО: {ip}\n"
        for ip in disconnected_devices:
            alert_msg += f"  ➖ УСТРОЙСТВО ОТКЛЮЧИЛОСЬ: {ip}\n"
        alert_msg += "\n"

    try:
        with open(HISTORY_FILE, "w") as f:
            json.dump(list(current_ips), f)
    except Exception as e:
        print(f"Ошибка записи истории хостов: {e}")

    list_render = "\n".join(devices_display) if devices_display else "  └ Нет активных хостов"
    return list_render, alert_msg, len(current_ips)

async def get_metrics():
    print("🚀 Запуск браузера Playwright...")
    local_devices_list, alert_block, nmap_count = scan_local_network()
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context(ignore_https_errors=True)
        page = await context.new_page()
        try:
            print(f"🌐 Открываем веб-интерфейс http://{ROUTER_IP}...")
            await page.goto(f"http://{ROUTER_IP}", timeout=15000)
            await page.wait_for_timeout(3000)
            print("🔑 Вводим пароль администратора...")
            await page.fill("input[type='password']", ROUTER_PASSWORD)
            await page.wait_for_timeout(500)
            print("Нажимаем кнопку Войти...")
            login_selectors = ["text=Войти", "text=Log In", "input[type='button']", ".login-btn", "button"]
            clicked = False
            for selector in login_selectors:
                try:
                    if await page.is_visible(selector):
                        await page.click(selector)
                        clicked = True
                        break
                except:
                    continue
            if not clicked:
                await page.press("input[type='password']", "Enter")
            print("⏳ Ожидаем прогрузки главной страницы...")
            await page.wait_for_timeout(8000)
            # Переход на вкладку Интернет для WAN IP и Uptime
            try:
                await page.click("text=Интернет")
                await page.wait_for_timeout(5000)
            except:
                pass
            # Сбор метрик через JavaScript
            metrics = await page.evaluate('''() => {
                function getText(selector) {
                    let el = document.querySelector(selector);
                    return el ? el.innerText.trim() : null;
                }
                let clients = "0";
                let clientEl = document.querySelector('.map-clients-icon-num');
                if (clientEl) {
                    let num = clientEl.innerText.match(/\\d+/);
                    if (num) clients = num[0];
                }
                let wanIP = "N/A";
                let lanIP = "N/A";
                let labels = document.querySelectorAll('.text-fieldlabel');
                for (let label of labels) {
                    if (label.innerText.includes('Интернет IP-адрес')) {
                        let parent = label.closest('.displaylabel-container');
                        if (parent) {
                            let value = parent.querySelector('.text-wrap-display');
                            if (value) wanIP = value.innerText.trim();
                        }
                    }
                    if (label.innerText.includes('IPv4 LAN IP-адрес')) {
                        let parent = label.closest('.displaylabel-container');
                        if (parent) {
                            let value = parent.querySelector('.text-wrap-display');
                            if (value) lanIP = value.innerText.trim();
                        }
                    }
                }
                let uptime = "N/A";
                let allText = document.body.innerText;
                let uptimeMatch = allText.match(/(?:Uptime|Время работы|Duration|Connection Time)\\s*[:：]\\s*([^\\n]+)/i);
                if (uptimeMatch) uptime = uptimeMatch[1].trim();
                let wifi24 = "Выключен";
                let wifi24Switch = document.querySelector('#wireless2g-enable-switch .switch-label');
                if (wifi24Switch && wifi24Switch.classList.contains('checked')) wifi24 = "Включен";
                let wifi5 = "Выключен";
                let wifi5Switch = document.querySelector('#wireless5g-enable-switch .switch-label');
                if (wifi5Switch && wifi5Switch.classList.contains('checked')) wifi5 = "Включен";
                let ssid24 = "N/A";
                let ssid24El = document.querySelector('#wireless2g-panel .displaylabel-container .text-wrap-display');
                if (ssid24El) ssid24 = ssid24El.innerText.trim();
                let ssid5 = "N/A";
                let ssid5El = document.querySelector('#wireless5g-panel .displaylabel-container .text-wrap-display');
                if (ssid5El) ssid5 = ssid5El.innerText.trim();
                return { clients, wanIP, lanIP, uptime, wifi24, wifi5, ssid24, ssid5 };
            }''')
            await page.screenshot(path="router_page.png")
            print("📸 Скриншот сохранён в ~/router_page.png")
            msg = (
                f"{alert_block}"
                f"📡 Метрики роутера\n\n"
                f"🕒 Uptime соединения: {metrics['uptime']}\n"
                f"📶 Устройств в сети (Nmap Скан): {nmap_count}\n"
                f"🌐 WAN IP: {metrics['wanIP']}\n"
                f"🏠 LAN IP: {metrics['lanIP']}\n\n"
                f"📶 Статус Wi-Fi сетей:\n"
                f"└ 2.4 GHz: {metrics['wifi24']} (SSID: {metrics['ssid24']})\n"
                f"└ 5 GHz: {metrics['wifi5']} (SSID: {metrics['ssid5']})\n\n"
                f"📋 Список IP-адресов онлайн:\n"
                f"{local_devices_list}\n\n"
                f"✅ Мониторинг успешно обновлен локально."
            )
        except Exception as e:
            msg = f"❌ Ошибка внутри браузера Playwright: {e}"
        finally:
            await browser.close()
        return msg

def send_tg(text_msg):
    import requests
    url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
    try:
        r = requests.post(url, json={"chat_id": CHAT_ID, "text": text_msg, "parse_mode": "HTML"}, timeout=15)
        if r.status_code == 200:
            print("✅ Отчет доставлен!")
        else:
            print(f"❌ Ошибка Telegram: {r.status_code} {r.text}")
    except Exception as e:
        print(f"❌ Ошибка отправки: {e}")

if __name__ == "__main__":
    report = asyncio.run(get_metrics())
    print("\n==========================================")
    print(report)
    print("==========================================\n")
    send_tg(report)
