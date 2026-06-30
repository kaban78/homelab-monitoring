#!/usr/bin/env python3
"""
Мониторинг сети, Pi-hole, SSH-атак, интернета, диска, портов, обновлений, Fail2Ban.
Команды Telegram: /status, /stats, /network, /block IP, /help, /reboot, /update, /backup.
"""

import os
import time
import re
import subprocess
import threading
import requests
import socket
import shutil
import zipfile
from datetime import datetime
from collections import defaultdict

# ==================== ЧТЕНИЕ ПЕРЕМЕННЫХ ИЗ ОКРУЖЕНИЯ ====================
TELEGRAM_TOKEN = os.getenv("TELEGRAM_TOKEN")
CHAT_ID = os.getenv("CHAT_ID")
PIHOLE_PASSWORD = os.getenv("PIHOLE_PASSWORD")
PIHOLE_API_URL = os.getenv("PIHOLE_API_URL", "http://192.168.10.2/api")
PROXY_HOST = os.getenv("PROXY_HOST", "127.0.0.1")
PROXY_PORT = os.getenv("PROXY_PORT", "1080")
SUBNETS = os.getenv("SUBNETS", "192.168.10.0/24,192.168.20.0/24,192.168.30.0/24").split(",")

# Проверка обязательных переменных
if not TELEGRAM_TOKEN or not CHAT_ID:
    print("❌ Ошибка: TELEGRAM_TOKEN и CHAT_ID должны быть заданы в .env")
    exit(1)

USE_PROXY = True  # можно сделать переменной, но пока оставим
proxies = {
    'http': f'socks5://{PROXY_HOST}:{PROXY_PORT}',
    'https': f'socks5://{PROXY_HOST}:{PROXY_PORT}',
} if USE_PROXY else None

# ==================== ОСТАЛЬНЫЕ НАСТРОЙКИ ====================
ARP_SCAN_INTERVAL = 60
INTERNET_CHECK_INTERVAL = 60
PIHOLE_STATS_INTERVAL = 3600
DISK_CHECK_INTERVAL = 3600
PORT_SCAN_INTERVAL = 3600
UPDATE_CHECK_INTERVAL = 86400
PIHOLE_HEALTH_INTERVAL = 300

DISK_THRESHOLD_PERCENT = 10
PORTS_TO_SCAN = [22, 80, 443]
FAIL2BAN_LOG = "/var/log/fail2ban.log"

known_devices = set()
devices_lock = threading.Lock()
pending_commands = {}

# =============================================================

def send_telegram(msg):
    url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
    try:
        r = requests.post(url, json={
            "chat_id": CHAT_ID,
            "text": msg,
            "parse_mode": "HTML"
        }, proxies=proxies, timeout=10)
        if r.status_code != 200:
            print(f"Ошибка отправки: {r.status_code} {r.text}")
    except Exception as e:
        print(f"Ошибка при запросе: {e}")

# ==================== МОНИТОРИНГ SSH ====================
def ssh_monitor():
    cmd = ["journalctl", "-f", "-n", "0", "-o", "cat", "-u", "sshd"]
    try:
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    except Exception as e:
        send_telegram(f"⚠️ Не удалось запустить journalctl: {e}")
        return
    attacks = {}
    ATTACK_WINDOW = 60
    for line in iter(p.stdout.readline, ""):
        if not line:
            break
        if "Failed password" in line or "Invalid user" in line:
            match = re.search(r"from (\d+\.\d+\.\d+\.\d+)", line)
            if match:
                ip = match.group(1)
                now = time.time()
                if ip in attacks:
                    attacks[ip]['count'] += 1
                else:
                    attacks[ip] = {'count': 1, 'first_seen': now}
                if attacks[ip]['count'] >= 5 and now - attacks[ip]['first_seen'] <= ATTACK_WINDOW:
                    msg = (
                        f"🚨 <b>Обнаружена атака</b>\n"
                        f"🔹 IP: <code>{ip}</code>\n"
                        f"🔸 Попыток: {attacks[ip]['count']} за {ATTACK_WINDOW} с"
                    )
                    send_telegram(msg)
                    attacks[ip]['count'] = 0
        time.sleep(0.1)

# ==================== СКАНИРОВАНИЕ СЕТИ ====================
def get_network_ips():
    devices = []
    for subnet in SUBNETS:
        try:
            output = subprocess.check_output(
                ["nmap", "-sn", "-PE", "-PS22,80,443", "-PA22,80,443", "--send-ip", subnet],
                stderr=subprocess.STDOUT, text=True
            )
            for line in output.splitlines():
                if "Nmap scan report for" in line:
                    ip_match = re.search(r'\((\d+\.\d+\.\d+\.\d+)\)', line)
                    if ip_match:
                        ip = ip_match.group(1)
                    else:
                        parts = line.split()
                        for part in reversed(parts):
                            if re.match(r'\d+\.\d+\.\d+\.\d+', part):
                                ip = part
                                break
                    if ip:
                        devices.append(ip)
        except Exception as e:
            print(f"Ошибка сканирования {subnet}: {e}")
    return devices

def arp_monitor():
    global known_devices
    while True:
        try:
            current_ips = set(get_network_ips())
            with devices_lock:
                new_ips = current_ips - known_devices
                lost_ips = known_devices - current_ips
                known_devices = current_ips
            for ip in new_ips:
                send_telegram(f"🟢 <b>Новое устройство</b>\n🔹 IP: {ip}")
            for ip in lost_ips:
                send_telegram(f"🔴 <b>Устройство отключилось</b>\n🔹 IP: {ip}")
        except Exception as e:
            print(f"ARP monitor error: {e}")
        time.sleep(ARP_SCAN_INTERVAL)

# ==================== ПРОВЕРКА ИНТЕРНЕТА ====================
def check_internet():
    while True:
        time.sleep(INTERNET_CHECK_INTERVAL)
        try:
            socket.create_connection(("8.8.8.8", 53), timeout=5)
        except Exception:
            send_telegram("⚠️ <b>Потеря интернета!</b> Нет связи с 8.8.8.8")

# ==================== СТАТИСТИКА PI-HOLE ====================
def get_pihole_stats():
    session = requests.Session()
    session.proxies = {}
    session.trust_env = False
    login_url = f"{PIHOLE_API_URL}/auth"
    try:
        r = session.post(login_url, json={"password": PIHOLE_PASSWORD}, timeout=5)
        if r.status_code != 200:
            return None, f"❌ Ошибка авторизации: статус {r.status_code}"
        data = r.json()
        if "error" in data:
            return None, f"❌ Ошибка авторизации: {data['error'].get('message', 'неизвестная ошибка')}"
        csrf_token = data.get('session', {}).get('csrf')
        if not csrf_token:
            return None, "❌ CSRF-токен не получен"
    except Exception as e:
        return None, f"❌ Ошибка при логине: {e}"

    stats_url = f"{PIHOLE_API_URL}/stats/summary"
    headers = {"X-CSRF-Token": csrf_token}
    try:
        r = session.get(stats_url, headers=headers, timeout=5)
        if r.status_code != 200:
            return None, f"❌ Ошибка API: статус {r.status_code}"
        data = r.json()
        if "error" in data:
            return None, f"❌ Ошибка API: {data['error'].get('message', 'неизвестная ошибка')}"
        queries = data.get('queries', {})
        total = queries.get('total', 0)
        blocked = queries.get('blocked', 0)
        percent = queries.get('percent_blocked', 0.0)
        top_blocked = data.get('top_blocked', {})
        top_list = ""
        if top_blocked:
            top_list = "\n🔝 <b>Топ-5 заблокированных:</b>\n"
            items = list(top_blocked.items())[:5] if isinstance(top_blocked, dict) else top_blocked[:5]
            for i, item in enumerate(items, 1):
                if isinstance(item, (list, tuple)):
                    domain, count = item[0], item[1]
                else:
                    domain, count = item, 0
                top_list += f"  {i}. {domain} – {count} запросов\n"
        msg = (f"📊 <b>Статистика Pi-hole</b>\n"
               f"🔹 Всего запросов: {total}\n"
               f"🔹 Заблокировано: {blocked} ({percent:.1f}%)\n"
               f"{top_list}")
        return data, msg
    except Exception as e:
        return None, f"❌ Ошибка получения статистики: {e}"

def periodic_pihole_stats():
    while True:
        time.sleep(PIHOLE_STATS_INTERVAL)
        try:
            _, msg = get_pihole_stats()
            send_telegram(msg)
        except Exception as e:
            print(f"Pi-hole stats error: {e}")

def pihole_health_monitor():
    failures = 0
    while True:
        time.sleep(PIHOLE_HEALTH_INTERVAL)
        data, _ = get_pihole_stats()
        if data is None:
            failures += 1
            if failures == 3:
                send_telegram("🚨 <b>Pi‑hole недоступен!</b> API не отвечает в течение 15 минут.")
        else:
            if failures >= 3:
                send_telegram("✅ <b>Pi‑hole снова доступен.</b>")
            failures = 0

# ==================== КОНТРОЛЬ ДИСКА ====================
def check_disk_space():
    while True:
        time.sleep(DISK_CHECK_INTERVAL)
        try:
            usage = shutil.disk_usage("/")
            percent_free = 100 * usage.free / usage.total
            if percent_free < DISK_THRESHOLD_PERCENT:
                send_telegram(
                    f"⚠️ <b>Мало свободного места!</b>\n"
                    f"Осталось {percent_free:.1f}% (< {DISK_THRESHOLD_PERCENT}%)"
                )
        except Exception as e:
            print(f"Ошибка проверки диска: {e}")

# ==================== СКАНИРОВАНИЕ ПОРТОВ ====================
def get_open_ports(ip_list):
    if not ip_list:
        return {}
    try:
        import nmap
    except ImportError:
        print("python-nmap не установлен.")
        return {}
    nm = nmap.PortScanner()
    open_ports = {}
    ips_str = " ".join(ip_list)
    try:
        nm.scan(hosts=ips_str,
                arguments=f'-p {",".join(map(str, PORTS_TO_SCAN))} -T4 --open')
        for host in nm.all_hosts():
            ports = []
            for proto in nm[host].all_protocols():
                ports.extend(
                    port for port in nm[host][proto]
                    if nm[host][proto][port]['state'] == 'open'
                )
            if ports:
                open_ports[host] = sorted(ports)
    except Exception as e:
        print(f"Ошибка сканирования портов: {e}")
    return open_ports

def port_scan_monitor():
    known_ports = defaultdict(set)
    while True:
        time.sleep(PORT_SCAN_INTERVAL)
        with devices_lock:
            current_ips = list(known_devices)
        if not current_ips:
            continue
        open_ports = get_open_ports(current_ips)
        for ip, ports in open_ports.items():
            new_ports = set(ports) - known_ports[ip]
            if new_ports:
                msg = (
                    f"🔍 <b>Новые открытые порты</b>\n"
                    f"🔹 IP: {ip}\n"
                    f"🔹 Порты: {', '.join(map(str, sorted(new_ports)))}"
                )
                send_telegram(msg)
            known_ports[ip] = set(ports)
        for ip in list(known_ports.keys()):
            if ip not in current_ips:
                del known_ports[ip]

# ==================== ОБНОВЛЕНИЯ ====================
def check_updates():
    while True:
        time.sleep(UPDATE_CHECK_INTERVAL)
        try:
            result = subprocess.run(
                ["apt", "list", "--upgradable", "-q"],
                capture_output=True, text=True
            )
            upgradable = result.stdout.strip()
            if upgradable and "listing..." not in upgradable:
                lines = [l for l in upgradable.splitlines() if l and not l.startswith("Listing")]
                count = len(lines)
                if count > 0:
                    packages = "\n".join(lines[:10])
                    if count > 10:
                        packages += f"\n... и ещё {count-10}"
                    send_telegram(f"📦 <b>Доступны обновления ({count} пакетов)</b>\n{packages}")
        except Exception as e:
            print(f"Ошибка проверки обновлений: {e}")

# ==================== FAIL2BAN ====================
def fail2ban_monitor():
    if not os.path.exists(FAIL2BAN_LOG):
        send_telegram("⚠️ Файл fail2ban.log не найден. Fail2Ban мониторинг отключён.")
        return
    try:
        proc = subprocess.Popen(
            ['tail', '-F', FAIL2BAN_LOG],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
    except Exception as e:
        send_telegram(f"⚠️ Не удалось запустить tail: {e}")
        return
    banned_ips = set()
    for line in proc.stdout:
        match = re.search(r"Ban\s+(\d+\.\d+\.\d+\.\d+)", line)
        if match:
            ip = match.group(1)
            if ip not in banned_ips:
                banned_ips.add(ip)
                jail_match = re.search(r"\[(.*?)\]", line)
                jail = jail_match.group(1) if jail_match else "unknown"
                send_telegram(
                    f"⛔ <b>Fail2Ban заблокировал IP</b>\n"
                    f"🔹 IP: {ip}\n"
                    f"🔹 Jail: {jail}"
                )

# ==================== ОБРАБОТКА КОМАНД ====================
def handle_commands():
    last_update_id = 0
    url_get = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/getUpdates"
    while True:
        try:
            params = {"offset": last_update_id + 1, "timeout": 30}
            r = requests.get(url_get, params=params, proxies=proxies, timeout=35)
            if r.status_code == 200:
                updates = r.json()
                if updates.get("ok") and updates.get("result"):
                    for update in updates["result"]:
                        last_update_id = update["update_id"]
                        message = update.get("message")
                        if not message:
                            continue
                        chat = message.get("chat")
                        if not chat:
                            continue
                        chat_id = str(chat.get("id"))
                        text = message.get("text")
                        if not text:
                            continue
                        if chat_id in pending_commands:
                            cmd_info = pending_commands[chat_id]
                            if time.time() < cmd_info['expires']:
                                if text.strip().lower() == 'да':
                                    execute_confirmed_command(chat_id, cmd_info['command'])
                                else:
                                    send_telegram("❌ Действие отменено.")
                                del pending_commands[chat_id]
                                continue
                            else:
                                del pending_commands[chat_id]
                        if text.startswith("/"):
                            process_command(text.strip(), chat_id)
        except Exception as e:
            print(f"Ошибка получения обновлений: {e}")
        time.sleep(1)

def process_command(text, chat_id):
    raw_cmd = text.lower().strip()
    cmd = re.sub(r'@\w+', '', raw_cmd).strip()

    if cmd == "/status":
        msg = (
            "🤖 <b>Бот работает</b>\n"
            f"🕒 Запущен: {datetime.now().strftime('%d.%m.%Y %H:%M:%S')}\n"
            "📡 Активные функции:\n"
            "• SSH-мониторинг\n"
            "• ARP-мониторинг (каждую минуту)\n"
            "• Проверка интернета (каждую минуту)\n"
            "• Статистика Pi-hole (каждый час)\n"
            "• Мониторинг доступности Pi-hole (каждые 5 мин)\n"
            "• Контроль диска (каждый час)\n"
            "• Сканирование портов (каждый час)\n"
            "• Обновления (раз в сутки)\n"
            "• Fail2Ban мониторинг"
        )
        send_telegram(msg)

    elif cmd == "/stats":
        _, msg = get_pihole_stats()
        send_telegram(msg)

    elif cmd == "/network":
        with devices_lock:
            devices = sorted(known_devices) if known_devices else get_network_ips()
        if devices:
            total = len(devices)
            msg = f"🌐 <b>Устройства в сети ({total})</b>\n\n"
            for ip in devices[:20]:
                msg += f"• IP: {ip}\n"
            if total > 20:
                msg += f"\n... и ещё {total-20}"
        else:
            msg = "❌ Не удалось получить список устройств."
        send_telegram(msg)

    elif cmd.startswith("/block "):
        ip = cmd.split(maxsplit=1)[1]
        if re.match(r'^\d+\.\d+\.\d+\.\d+$', ip):
            try:
                subprocess.run(
                    ["sudo", "/sbin/iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
                    check=True
                )
                send_telegram(f"✅ IP {ip} заблокирован через iptables.")
            except Exception as e:
                send_telegram(f"❌ Ошибка блокировки: {e}")
        else:
            send_telegram("❌ Неверный IP-адрес.")

    elif cmd == "/help":
        msg = (
            "<b>Доступные команды:</b>\n"
            "/status – статус бота\n"
            "/stats – статистика Pi-hole\n"
            "/network – список устройств\n"
            "/block &lt;IP&gt; – заблокировать IP\n"
            "/reboot – перезагрузить систему (с подтверждением)\n"
            "/update – обновить систему (apt upgrade, с подтверждением)\n"
            "/backup – создать бэкап конфигов\n"
            "/help – эта справка"
        )
        send_telegram(msg)

    elif cmd == "/reboot":
        if chat_id != CHAT_ID:
            send_telegram("⛔ Команда разрешена только администратору.")
            return
        pending_commands[chat_id] = {
            'command': 'reboot',
            'expires': time.time() + 30
        }
        send_telegram("⚠️ <b>Подтвердите перезагрузку</b>. Напишите <b>да</b> в течение 30 секунд.")

    elif cmd == "/update":
        if chat_id != CHAT_ID:
            send_telegram("⛔ Команда разрешена только администратору.")
            return
        pending_commands[chat_id] = {
            'command': 'update',
            'expires': time.time() + 30
        }
        send_telegram("⚠️ <b>Подтвердите обновление системы</b>. Напишите <b>да</b> в течение 30 секунд.")

    elif cmd == "/backup":
        if chat_id != CHAT_ID:
            send_telegram("⛔ Команда разрешена только администратору.")
            return
        backup_result = create_backup()
        send_telegram(backup_result)

    else:
        send_telegram("❌ Неизвестная команда. Введите /help.")

def execute_confirmed_command(chat_id, command):
    if command == 'reboot':
        send_telegram("🔄 Выполняется перезагрузка...")
        subprocess.run(["sudo", "reboot"])
    elif command == 'update':
        send_telegram("📦 Запущено обновление пакетов...")
        try:
            subprocess.run(["sudo", "apt", "update"], check=True)
            subprocess.run(["sudo", "apt", "upgrade", "-y"], check=True)
            send_telegram("✅ Система обновлена. Рекомендуется перезагрузка.")
        except Exception as e:
            send_telegram(f"❌ Ошибка при обновлении: {e}")

def create_backup():
    backup_dir = "/home/ros/backup"
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    zip_name = f"{backup_dir}/backup_{timestamp}.zip"
    skipped = []
    try:
        os.makedirs(backup_dir, exist_ok=True)
        with zipfile.ZipFile(zip_name, 'w') as zf:
            if os.path.exists("/etc/pihole"):
                for root, dirs, files in os.walk("/etc/pihole"):
                    for file in files:
                        full_path = os.path.join(root, file)
                        try:
                            zf.write(full_path,
                                     os.path.relpath(full_path, "/etc"))
                        except PermissionError:
                            skipped.append(full_path)
            if os.path.exists("/home/ros/network-bot/bot.py"):
                zf.write("/home/ros/network-bot/bot.py", "bot.py")
            with open("/tmp/packages.txt", "w") as f:
                subprocess.run(["dpkg", "--get-selections"], stdout=f)
            zf.write("/tmp/packages.txt", "packages.txt")
        if skipped:
            return f"✅ Бэкап создан: {zip_name}\n⚠️ Пропущены файлы без прав: {', '.join(skipped)}"
        return f"✅ Бэкап создан: {zip_name}"
    except Exception as e:
        return f"❌ Ошибка создания бэкапа: {e}"

# ==================== ЗАПУСК ====================
def main():
    global known_devices
    known_devices = set(get_network_ips())

    proxy_msg = "Используется прокси." if USE_PROXY else "Прокси отключён."
    send_telegram(f"🤖 Бот запущен. {proxy_msg}")

    threading.Thread(target=check_updates_once, daemon=True).start()

    threads = [
        threading.Thread(target=ssh_monitor, daemon=True),
        threading.Thread(target=arp_monitor, daemon=True),
        threading.Thread(target=check_internet, daemon=True),
        threading.Thread(target=periodic_pihole_stats, daemon=True),
        threading.Thread(target=pihole_health_monitor, daemon=True),
        threading.Thread(target=check_disk_space, daemon=True),
        threading.Thread(target=port_scan_monitor, daemon=True),
        threading.Thread(target=check_updates, daemon=True),
        threading.Thread(target=fail2ban_monitor, daemon=True),
        threading.Thread(target=handle_commands, daemon=True),
    ]

    for t in threads:
        t.start()

    while True:
        time.sleep(1)

def check_updates_once():
    try:
        result = subprocess.run(
            ["apt", "list", "--upgradable", "-q"],
            capture_output=True, text=True
        )
        upgradable = result.stdout.strip()
        if upgradable and "listing..." not in upgradable:
            lines = [l for l in upgradable.splitlines() if l and not l.startswith("Listing")]
            count = len(lines)
            if count > 0:
                packages = "\n".join(lines[:10])
                if count > 10:
                    packages += f"\n... и ещё {count-10}"
                send_telegram(f"📦 <b>Доступны обновления ({count} пакетов)</b>\n{packages}")
    except Exception as e:
        print(f"Первая проверка обновлений: {e}")

if __name__ == "__main__":
    main()
