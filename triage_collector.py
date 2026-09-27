#!/usr/bin/env python3
"""
IR-Collector — сбор первичных данных на подозрительной машине.

Скрипт собирает информацию о системе, процессах, сетевых соединениях
и неудачных входах, проверяет внешние IP в AbuseIPDB и складывает всё
в папку IR_Collected_Data_YYYYMMDD_HHMMSS.

Запуск:
    python triage_collector.py
    python triage_collector.py --log-file sample_logs/auth.log
"""

import argparse
import collections
import csv
import datetime
import getpass
import hashlib
import ipaddress
import json
import logging
import os
import platform
import re
import shutil
import socket
import subprocess
import sys

import psutil
import requests


# Настройки по умолчанию. Их можно поменять в config.json.
DEFAULT_CONFIG = {
    "abuseipdb_api_key": "",
    "abuseipdb_max_age_days": 90,
    "max_ips_to_check": 50,            # бесплатный тариф — 1000 запросов в день
    "suspicious_score_threshold": 25,  # с какого рейтинга считаем IP подозрительным
    "request_timeout_seconds": 10,
    "log_files": [
        "/var/log/auth.log",    # Ubuntu / Debian
        "/var/log/secure",      # CentOS / RHEL
        "/var/log/system.log",  # macOS
    ],
    "failed_login_keywords": [
        "Failed password",
        "Invalid user",
        "authentication failure",
        "Logon Failure",
        "An account failed to log on",
    ],
    "export_system_log": True,
    "windows_max_events": 500,
    "journal_days": 7,
}

CONFIG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")
ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"

# Имена файлов с результатами
RUN_LOG_FILE = "script_run.log"
SYSTEM_INFO_FILE = "system_info.json"
NETWORK_FILE = "network_connections.txt"
PROCESSES_FILE = "processes.csv"
SYSTEM_LOG_EXPORT_FILE = "system_log_export.txt"
FAILED_LOGINS_FILE = "failed_logins.txt"
EXTERNAL_IPS_FILE = "external_ips.txt"
SUSPICIOUS_IPS_FILE = "suspicious_ips.json"
SUMMARY_FILE = "Summary_Report.txt"
HASHES_FILE = "hashes_sha256.txt"

ACCESS_DENIED = "ACCESS_DENIED"

PROCESS_FIELDS = ["pid", "ppid", "name", "username", "exe", "cmdline", "create_time", "status"]

# Нормальные программы редко запускаются из этих папок, а вирусы — часто
SUSPICIOUS_FOLDERS = [
    "/tmp/",
    "/var/tmp/",
    "/dev/shm/",
    "/appdata/local/temp/",
    "/windows/temp/",
    "/users/public/",
    "/downloads/",
]

IP_REGEX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

logger = logging.getLogger("ir_collector")


# ---------------------------------------------------------------------------
# Вспомогательные функции
# ---------------------------------------------------------------------------

def parse_arguments():
    parser = argparse.ArgumentParser(description="Basic-IR-Collector: сбор данных при инциденте")
    parser.add_argument("--config", default=CONFIG_PATH, help="путь к config.json")
    parser.add_argument("--log-file", action="append", default=[], metavar="PATH",
                        help="дополнительный лог для анализа (можно указать несколько раз)")
    parser.add_argument("--output-base", default=".", metavar="DIR",
                        help="куда сохранить результаты (например, на флешку)")
    return parser.parse_args()


def create_output_directory(base_dir):
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = os.path.abspath(os.path.join(base_dir, f"IR_Collected_Data_{timestamp}"))
    os.makedirs(output_dir, exist_ok=True)
    return output_dir


def setup_logging(output_dir):
    # Пишем лог и в консоль, и в файл script_run.log
    logger.setLevel(logging.INFO)
    formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S")

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    file_handler = logging.FileHandler(os.path.join(output_dir, RUN_LOG_FILE), encoding="utf-8")
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)


def load_config(config_path):
    config = dict(DEFAULT_CONFIG)
    if os.path.isfile(config_path):
        with open(config_path, "r", encoding="utf-8") as config_file:
            config.update(json.load(config_file))
        logger.info("Загружены настройки из %s", config_path)
    else:
        logger.info("config.json не найден, используются настройки по умолчанию")
    return config


def is_running_as_admin():
    if os.name == "nt":
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    return os.geteuid() == 0


def run_step(step_name, step_function, *args):
    # Если один шаг упал, остальные всё равно выполнятся
    logger.info("---- %s ----", step_name)
    try:
        return step_function(*args)
    except Exception:
        logger.exception("Ошибка на шаге «%s», идём дальше", step_name)
        return None


def format_time(unix_time):
    return datetime.datetime.fromtimestamp(unix_time).strftime("%Y-%m-%d %H:%M:%S")


def save_json(path, data):
    with open(path, "w", encoding="utf-8") as json_file:
        json.dump(data, json_file, ensure_ascii=False, indent=4)


def save_text(path, lines):
    with open(path, "w", encoding="utf-8") as text_file:
        text_file.write("\n".join(lines) + "\n")


def yes_no(value):
    return "да" if value else "нет"


def get_local_ips():
    # Свои IP-адреса машины проверять не нужно
    local_ips = set()
    for addresses in psutil.net_if_addrs().values():
        for address in addresses:
            if address.family in (socket.AF_INET, socket.AF_INET6):
                local_ips.add(address.address.split("%")[0])
    return local_ips


# ---------------------------------------------------------------------------
# Шаг 2. Состояние системы
# ---------------------------------------------------------------------------

def collect_system_info(output_dir, is_admin):
    # Кто работает на машине, какая ОС и когда была последняя перезагрузка
    sessions = []
    for session in psutil.users():
        sessions.append({
            "name": session.name,
            "terminal": session.terminal,
            "remote_host": session.host,  # откуда подключились (SSH, RDP)
            "started": format_time(session.started),
        })

    interfaces = {}
    for name, addresses in psutil.net_if_addrs().items():
        ips = [a.address for a in addresses if a.family in (socket.AF_INET, socket.AF_INET6)]
        if ips:
            interfaces[name] = ips

    boot_time = psutil.boot_time()
    uptime = datetime.datetime.now() - datetime.datetime.fromtimestamp(boot_time)

    system_info = {
        "collection_time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "hostname": socket.gethostname(),
        "current_user": getpass.getuser(),
        "is_admin": is_admin,
        "os_name": platform.system(),
        "os_release": platform.release(),
        "os_version": platform.version(),
        "platform": platform.platform(),
        "architecture": platform.machine(),
        "boot_time": format_time(boot_time),
        "uptime": str(uptime).split(".")[0],
        "logged_in_users": sessions,
        "network_interfaces": interfaces,
    }

    save_json(os.path.join(output_dir, SYSTEM_INFO_FILE), system_info)
    logger.info("Хост: %s, пользователь: %s, ОС: %s",
                system_info["hostname"], system_info["current_user"], system_info["platform"])
    return system_info


def get_process_name(pid, name_cache):
    if pid is None:
        return "-"
    if pid not in name_cache:
        try:
            name_cache[pid] = psutil.Process(pid).name()
        except psutil.Error:  # нет прав или процесс уже завершился
            name_cache[pid] = ACCESS_DENIED
    return name_cache[pid]


def format_address(address):
    if not address:
        return "-"
    return f"{address.ip}:{address.port}"


def collect_network_connections(output_dir):
    # Смотрим, какие процессы и куда подключаются. Тут можно найти связь с C2-сервером.
    connections = []
    is_complete = True
    try:
        for conn in psutil.net_connections(kind="inet"):
            connections.append((conn.pid, conn))
    except psutil.AccessDenied:
        # На macOS полный список доступен только root, поэтому собираем по процессам
        is_complete = False
        logger.warning("Нет прав на полный список соединений, данные будут неполными")
        for process in psutil.process_iter():
            try:
                for conn in process.net_connections(kind="inet"):
                    connections.append((process.pid, conn))
            except psutil.Error:
                continue

    name_cache = {}
    rows = []
    for pid, conn in connections:
        protocol = "TCP" if conn.type == socket.SOCK_STREAM else "UDP"
        rows.append({
            "protocol": protocol,
            "local": format_address(conn.laddr),
            "remote": format_address(conn.raddr),
            "status": conn.status,
            "pid": pid,
            "process": get_process_name(pid, name_cache),
        })

    # Установленные соединения показываем первыми
    rows.sort(key=lambda row: row["status"] != "ESTABLISHED")

    established = sum(1 for row in rows if row["status"] == "ESTABLISHED")
    listening = sum(1 for row in rows if row["status"] == "LISTEN")

    lines = [
        f"Сетевые соединения: {socket.gethostname()}, {datetime.datetime.now():%Y-%m-%d %H:%M:%S}",
        f"Полный список: {yes_no(is_complete)}",
        f"Всего: {len(rows)} (ESTABLISHED: {established}, LISTEN: {listening})",
        "",
        f"{'PROTO':<7}{'LOCAL ADDRESS':<48}{'REMOTE ADDRESS':<48}{'STATUS':<14}{'PID':<8}PROCESS",
    ]
    for row in rows:
        lines.append(f"{row['protocol']:<7}{row['local']:<48}{row['remote']:<48}"
                     f"{row['status']:<14}{str(row['pid']):<8}{row['process']}")
    save_text(os.path.join(output_dir, NETWORK_FILE), lines)

    logger.info("Соединений: %d (ESTABLISHED: %d, LISTEN: %d)", len(rows), established, listening)
    return {"total": len(rows), "established": established, "listening": listening, "is_complete": is_complete}


def is_suspicious_path(exe_path):
    path = exe_path.lower().replace("\\", "/")
    return any(folder in path for folder in SUSPICIOUS_FOLDERS)


def collect_processes(output_dir):
    # Список процессов. Ищем странные имена, запуск из Temp, подозрительные команды.
    rows = []
    incomplete = 0

    for process in psutil.process_iter():
        try:
            # Если к какому-то полю нет доступа, туда запишется ACCESS_DENIED
            info = process.as_dict(attrs=PROCESS_FIELDS, ad_value=ACCESS_DENIED)
        except psutil.NoSuchProcess:
            continue  # процесс завершился, пока мы его читали

        if isinstance(info["cmdline"], list):
            info["cmdline"] = " ".join(info["cmdline"])
        if isinstance(info["create_time"], float):
            info["create_time"] = format_time(info["create_time"])
        info["exe"] = info["exe"] or ""
        info["suspicious_location"] = "yes" if is_suspicious_path(info["exe"]) else "no"

        if ACCESS_DENIED in info.values():
            incomplete += 1
        rows.append(info)

    rows.sort(key=lambda row: row["pid"])

    # utf-8-sig нужен, чтобы Excel нормально показал кириллицу
    with open(os.path.join(output_dir, PROCESSES_FILE), "w", newline="", encoding="utf-8-sig") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=PROCESS_FIELDS + ["suspicious_location"])
        writer.writeheader()
        writer.writerows(rows)

    suspicious = [row for row in rows if row["suspicious_location"] == "yes"]

    logger.info("Процессов: %d, из них с неполными данными: %d", len(rows), incomplete)
    for row in suspicious:
        logger.warning("Процесс из подозрительной папки: PID %s %s (%s)", row["pid"], row["name"], row["exe"])

    return {"total": len(rows), "incomplete": incomplete, "suspicious": suspicious}


# ---------------------------------------------------------------------------
# Шаг 3. Неудачные входы в логах
# ---------------------------------------------------------------------------

def export_system_log(output_dir, config, is_admin):
    # Выгружаем системный журнал в текстовый файл, чтобы искать в нём как в обычном логе
    system_name = platform.system()

    if system_name == "Windows":
        if not is_admin:
            logger.warning("Журнал Security доступен только администратору, пропускаю")
            return None
        # Событие 4625 — неудачный вход. Берём время, пользователя, IP и тип входа.
        script = (
            "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; "
            "Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} "
            "-MaxEvents " + str(config["windows_max_events"]) + " -ErrorAction SilentlyContinue | "
            "ForEach-Object { '{0} EventID=4625 Logon Failure: user={1} source_ip={2} logon_type={3}' -f "
            "$_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'), "
            "$_.Properties[5].Value, $_.Properties[19].Value, $_.Properties[10].Value }"
        )
        command = ["powershell.exe", "-NoProfile", "-Command", script]

    elif system_name == "Linux" and shutil.which("journalctl"):
        # 4 и 10 — категории auth и authpriv (ssh, sudo, su)
        command = ["journalctl", "--no-pager", "--quiet",
                   "--since", f"{config['journal_days']} days ago",
                   "SYSLOG_FACILITY=4", "SYSLOG_FACILITY=10"]

    else:
        return None

    logger.info("Выгружаю системный журнал (%s)", command[0])
    result = subprocess.run(command, capture_output=True, encoding="utf-8", errors="replace")
    if result.returncode != 0:
        logger.warning("Не удалось выгрузить журнал: %s", result.stderr.strip())
        return None

    export_path = os.path.join(output_dir, SYSTEM_LOG_EXPORT_FILE)
    with open(export_path, "w", encoding="utf-8") as export_file:
        export_file.write(result.stdout)
    return export_path


def search_log_file(log_path, keywords):
    # Читаем построчно: логи бывают очень большими
    keywords = [keyword.lower() for keyword in keywords]
    found_lines = []
    with open(log_path, "r", encoding="utf-8", errors="replace") as log_file:
        for line in log_file:
            if any(keyword in line.lower() for keyword in keywords):
                found_lines.append(line.strip())
    return found_lines


def find_ips_in_text(text):
    # Регулярка находит "что-то похожее на IP", а ipaddress отсеивает мусор вроде 999.1.1.1
    ips = []
    for candidate in IP_REGEX.findall(text):
        try:
            ipaddress.IPv4Address(candidate)
            ips.append(candidate)
        except ValueError:
            pass
    return ips


def collect_failed_logins(output_dir, config, extra_log_files, is_admin):
    # Много неудачных входов с одного IP — признак подбора пароля
    keywords = config["failed_login_keywords"]

    system_logs = [path for path in config["log_files"] if os.path.isfile(path)]
    files_to_scan = system_logs + [path for path in extra_log_files if os.path.isfile(path)]

    # На Windows текстовых логов нет. На Linux auth.log может не быть, тогда берём journald.
    if config["export_system_log"] and not system_logs:
        exported_file = export_system_log(output_dir, config, is_admin)
        if exported_file:
            files_to_scan.append(exported_file)

    results = {}
    for log_path in files_to_scan:
        try:
            results[log_path] = search_log_file(log_path, keywords)
        except PermissionError:
            logger.warning("Нет прав на чтение %s, нужен root/администратор", log_path)
            continue
        logger.info("%s: найдено строк %d", log_path, len(results[log_path]))

    total = sum(len(lines) for lines in results.values())

    # Считаем, с каких IP больше всего попыток
    attempts_by_ip = collections.Counter()
    for lines in results.values():
        for line in lines:
            for ip in set(find_ips_in_text(line)):
                attempts_by_ip[ip] += 1
    top_sources = attempts_by_ip.most_common(10)

    report = ["Неудачные попытки входа", f"Ключевые слова: {', '.join(keywords)}", ""]
    report.append("Проверенные файлы:")
    for log_path, lines in results.items():
        report.append(f"  {log_path}: {len(lines)}")
    report += ["", f"Всего найдено строк: {total}", ""]

    if top_sources:
        report.append("Топ IP по количеству попыток:")
        for ip, count in top_sources:
            report.append(f"  {ip:<18}{count}")
        report.append("")

    for log_path, lines in results.items():
        if lines:
            report.append(f"===== {log_path} =====")
            report += lines
            report.append("")

    save_text(os.path.join(output_dir, FAILED_LOGINS_FILE), report)
    logger.info("Неудачных входов найдено: %d", total)
    return {"total": total, "files_scanned": len(results), "top_sources": top_sources}


# ---------------------------------------------------------------------------
# Шаг 4. Проверка IP-адресов
# ---------------------------------------------------------------------------

def is_external_ip(ip, local_ips):
    # is_global отсекает 10.x, 172.16-31.x, 192.168.x, 127.x и другие служебные сети
    address = ipaddress.ip_address(ip)
    return address.is_global and not address.is_multicast and ip not in local_ips


def check_ips_in_abuseipdb(ip_list, config):
    api_key = os.environ.get("ABUSEIPDB_API_KEY") or config["abuseipdb_api_key"]
    if not api_key:
        logger.warning("Нет API-ключа AbuseIPDB, проверка пропущена")
        return "пропущена (нет API-ключа)", []

    ips_to_check = ip_list[:config["max_ips_to_check"]]
    headers = {"Key": api_key, "Accept": "application/json"}
    results = []

    for ip in ips_to_check:
        params = {"ipAddress": ip, "maxAgeInDays": config["abuseipdb_max_age_days"]}
        try:
            response = requests.get(ABUSEIPDB_URL, headers=headers, params=params,
                                    timeout=config["request_timeout_seconds"])
        except requests.exceptions.RequestException as error:
            logger.error("Ошибка сети при запросе к AbuseIPDB: %s", error)
            break

        if response.status_code != 200:
            # 401 — неверный ключ, 429 — закончился лимит запросов
            logger.error("AbuseIPDB вернул код %d, останавливаю проверку", response.status_code)
            break

        data = response.json()["data"]
        results.append({
            "ip": ip,
            "abuse_score": data["abuseConfidenceScore"],
            "total_reports": data["totalReports"],
            "country": data.get("countryCode"),
            "isp": data.get("isp"),
            "is_tor": data.get("isTor"),
            "last_reported_at": data.get("lastReportedAt"),
        })
        logger.info("%s: score %d", ip, data["abuseConfidenceScore"])

    status = f"проверено {len(results)} из {len(ip_list)} IP"
    return status, results


def analyze_ip_addresses(output_dir, config):
    # Ищем IP в файлах соединений и неудачных входов
    ip_sources = {}  # IP -> в каком файле нашли
    for filename in (NETWORK_FILE, FAILED_LOGINS_FILE):
        path = os.path.join(output_dir, filename)
        if not os.path.isfile(path):
            continue
        with open(path, "r", encoding="utf-8") as source_file:
            for ip in find_ips_in_text(source_file.read()):
                ip_sources.setdefault(ip, set()).add(filename)

    local_ips = get_local_ips()
    external_ips = [ip for ip in ip_sources if is_external_ip(ip, local_ips)]
    external_ips.sort(key=ipaddress.ip_address)
    logger.info("Уникальных IP: %d, из них внешних: %d", len(ip_sources), len(external_ips))

    # Список внешних IP сохраняем всегда, его можно проверить и вручную
    lines = [f"Внешние IP-адреса: {len(external_ips)}", ""]
    for ip in external_ips:
        lines.append(f"{ip:<18}{', '.join(sorted(ip_sources[ip]))}")
    save_text(os.path.join(output_dir, EXTERNAL_IPS_FILE), lines)

    status, results = check_ips_in_abuseipdb(external_ips, config)

    threshold = config["suspicious_score_threshold"]
    for result in results:
        result["found_in"] = sorted(ip_sources[result["ip"]])
    results.sort(key=lambda result: result["abuse_score"], reverse=True)
    suspicious = [result for result in results if result["abuse_score"] >= threshold]

    if results:
        save_json(os.path.join(output_dir, SUSPICIOUS_IPS_FILE), {
            "checked_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "score_threshold": threshold,
            "suspicious_ips": suspicious,
            "all_checked_ips": results,
        })
        logger.info("Подозрительных IP: %d", len(suspicious))

    return {
        "unique_ips": len(ip_sources),
        "external_ips": external_ips,
        "status": status,
        "threshold": threshold,
        "suspicious": suspicious,
    }


# ---------------------------------------------------------------------------
# Шаг 5. Итоговый отчёт
# ---------------------------------------------------------------------------

def write_summary_report(output_dir, start_time, end_time, system_info,
                         network_stats, process_stats, login_stats, ip_stats):
    failed = "ошибка, см. script_run.log"
    duration = (end_time - start_time).total_seconds()

    lines = ["=" * 60, "  BASIC-IR-COLLECTOR — ИТОГОВЫЙ ОТЧЁТ", "=" * 60]
    if system_info:
        lines += [
            f"Хост:              {system_info['hostname']}",
            f"Пользователь:      {system_info['current_user']} (админ: {yes_no(system_info['is_admin'])})",
            f"ОС:                {system_info['platform']}",
            f"Загрузка ОС:       {system_info['boot_time']}",
        ]
    lines += [
        f"Начало сбора:      {start_time:%Y-%m-%d %H:%M:%S}",
        f"Конец сбора:       {end_time:%Y-%m-%d %H:%M:%S}",
        f"Время работы:      {duration:.1f} сек.",
        "",
        "--- Процессы ---",
    ]

    if process_stats:
        lines.append(f"Собрано процессов: {process_stats['total']}")
        lines.append(f"С неполными данными: {process_stats['incomplete']}")
        lines.append(f"Из подозрительных папок: {len(process_stats['suspicious'])}")
        for process in process_stats["suspicious"]:
            lines.append(f"  PID {process['pid']} {process['name']} {process['exe']}")
    else:
        lines.append(failed)

    lines += ["", "--- Сетевые соединения ---"]
    if network_stats:
        lines.append(f"Всего: {network_stats['total']} "
                     f"(ESTABLISHED: {network_stats['established']}, LISTEN: {network_stats['listening']})")
        lines.append(f"Полный список: {yes_no(network_stats['is_complete'])}")
    else:
        lines.append(failed)

    lines += ["", "--- Неудачные входы ---"]
    if login_stats:
        lines.append(f"Найдены: {'ДА' if login_stats['total'] else 'нет'} (строк: {login_stats['total']})")
        lines.append(f"Проверено логов: {login_stats['files_scanned']}")
        for ip, count in login_stats["top_sources"][:5]:
            lines.append(f"  {ip:<18}попыток: {count}")
    else:
        lines.append(failed)

    lines += ["", "--- IP-адреса ---"]
    if ip_stats:
        lines.append(f"Уникальных внешних IP: {len(ip_stats['external_ips'])}")
        lines.append(f"Проверка AbuseIPDB: {ip_stats['status']}")
        lines.append(f"Подозрительных (score >= {ip_stats['threshold']}): {len(ip_stats['suspicious'])}")
        for result in ip_stats["suspicious"]:
            lines.append(f"  {result['ip']:<18}score={result['abuse_score']}  country={result['country']}  "
                         f"({', '.join(result['found_in'])})")
    else:
        lines.append(failed)

    lines += ["", f"Папка с результатами: {output_dir}"]
    save_text(os.path.join(output_dir, SUMMARY_FILE), lines)
    logger.info("Отчёт сохранён в %s", SUMMARY_FILE)


def write_file_hashes(output_dir):
    # Хэши нужны, чтобы потом доказать, что файлы не меняли после сбора.
    # Проверка: sha256sum -c hashes_sha256.txt
    lines = []
    for filename in sorted(os.listdir(output_dir)):
        if filename in (RUN_LOG_FILE, HASHES_FILE):
            continue
        with open(os.path.join(output_dir, filename), "rb") as collected_file:
            file_hash = hashlib.sha256(collected_file.read()).hexdigest()
        lines.append(f"{file_hash}  {filename}")
    save_text(os.path.join(output_dir, HASHES_FILE), lines)
    logger.info("Хэши файлов сохранены в %s", HASHES_FILE)


# ---------------------------------------------------------------------------
# Запуск
# ---------------------------------------------------------------------------

def main():
    args = parse_arguments()
    start_time = datetime.datetime.now()

    # Шаг 1. Подготовка
    output_dir = create_output_directory(args.output_base)
    setup_logging(output_dir)
    logger.info("Начинаю сбор, результаты будут в %s", output_dir)

    config = load_config(args.config)
    is_admin = is_running_as_admin()
    if not is_admin:
        logger.warning("Скрипт запущен без прав администратора, часть данных будет недоступна")

    # Сначала собираем то, что быстро меняется (соединения, процессы), потом логи
    system_info = run_step("Информация о системе", collect_system_info, output_dir, is_admin)
    network_stats = run_step("Сетевые соединения", collect_network_connections, output_dir)
    process_stats = run_step("Процессы", collect_processes, output_dir)
    login_stats = run_step("Неудачные входы", collect_failed_logins, output_dir, config, args.log_file, is_admin)
    ip_stats = run_step("Проверка IP-адресов", analyze_ip_addresses, output_dir, config)

    end_time = datetime.datetime.now()
    run_step("Итоговый отчёт", write_summary_report, output_dir, start_time, end_time,
             system_info, network_stats, process_stats, login_stats, ip_stats)
    run_step("Хэши файлов", write_file_hashes, output_dir)

    logger.info("Готово за %.1f сек.", (datetime.datetime.now() - start_time).total_seconds())


if __name__ == "__main__":
    main()
