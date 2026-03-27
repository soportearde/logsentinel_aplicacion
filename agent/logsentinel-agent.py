#!/usr/bin/env python3
"""
LogSentinel Agent — Agente ligero para servidores Ubuntu.

Se instala como servicio systemd y envía logs del sistema
al endpoint del LogCollector de LogSentinel.

Monitoriza:
  - /var/log/auth.log    → logins SSH, sudo, etc.
  - /var/log/syslog      → eventos generales del sistema
  - Logs de nginx/apache si existen
"""

import json
import time
import re
import os
import sys
import signal
import socket
import requests
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse


# ─────────────────────────────────────────────────────────────
# CONFIGURACIÓN (se sobreescribe con /etc/logsentinel/agent.conf)
# ─────────────────────────────────────────────────────────────

# URL del LogCollector (se configura durante la instalación)
LOGSENTINEL_URL = os.getenv("LOGSENTINEL_URL", "http://localhost:5000/log")

# API Key para autenticar este agente
API_KEY = os.getenv("LOGSENTINEL_API_KEY", "")

# Nombre del sistema (aparecerá en el dashboard)
SYSTEM_NAME = os.getenv("LOGSENTINEL_SYSTEM_NAME", socket.gethostname())

# Intervalo en segundos entre envíos de logs
SEND_INTERVAL = int(os.getenv("LOGSENTINEL_INTERVAL", "5"))

# Fichero donde guardamos la última posición leída de cada log
STATE_FILE = "/var/lib/logsentinel/agent_state.json"


# ─────────────────────────────────────────────────────────────
# ARCHIVOS DE LOG A MONITORIZAR
# ─────────────────────────────────────────────────────────────

# Lista de archivos con su source_system asociado
LOG_SOURCES = [
    {"path": "/var/log/auth.log",         "source_system": "ssh"},
    {"path": "/var/log/syslog",           "source_system": "linux_syslog"},
    {"path": "/var/log/nginx/access.log", "source_system": "nginx"},
    {"path": "/var/log/nginx/error.log",  "source_system": "nginx"},
    {"path": "/var/log/apache2/access.log", "source_system": "apache"},
    {"path": "/var/log/apache2/error.log",  "source_system": "apache"},
]


# ─────────────────────────────────────────────────────────────
# CARGA DE CONFIGURACIÓN DESDE FICHERO
# ─────────────────────────────────────────────────────────────

def load_config():
    """Lee la config de /etc/logsentinel/agent.conf si existe."""
    global LOGSENTINEL_URL, API_KEY, SYSTEM_NAME, SEND_INTERVAL

    config_path = "/etc/logsentinel/agent.conf"
    if not os.path.exists(config_path):
        return

    with open(config_path, "r") as f:
        config = json.load(f)

    LOGSENTINEL_URL = config.get("url", LOGSENTINEL_URL)
    API_KEY = config.get("api_key", API_KEY)
    SYSTEM_NAME = config.get("system_name", SYSTEM_NAME)
    SEND_INTERVAL = config.get("interval", SEND_INTERVAL)

    print(f"[LogSentinel Agent] Config cargada desde {config_path}")


# ─────────────────────────────────────────────────────────────
# ESTADO: recordar la última línea leída de cada fichero
# ─────────────────────────────────────────────────────────────

def load_state():
    """Carga el estado (posiciones de lectura) desde disco."""
    if os.path.exists(STATE_FILE):
        with open(STATE_FILE, "r") as f:
            return json.load(f)
    return {}

def save_state(state):
    """Guarda el estado a disco."""
    os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
    with open(STATE_FILE, "w") as f:
        json.dump(state, f)


# ─────────────────────────────────────────────────────────────
# PARSEO DE LÍNEAS DE LOG
# ─────────────────────────────────────────────────────────────

# Patrón para auth.log: "Mar 24 10:15:03 servidor sshd[1234]: mensaje"
AUTH_PATTERN = re.compile(
    r"^(\w+\s+\d+\s+[\d:]+)\s+(\S+)\s+(\S+?)(?:\[\d+\])?:\s+(.+)$"
)

# Patrón para detectar login SSH fallido
SSH_FAILED_PATTERN = re.compile(
    r"Failed password for (?:invalid user )?(\S+) from ([\d.]+)"
)

# Patrón para detectar login SSH exitoso
SSH_SUCCESS_PATTERN = re.compile(
    r"Accepted (?:password|publickey) for (\S+) from ([\d.]+)"
)

# Patrón para sudo
SUDO_PATTERN = re.compile(
    r"sudo:\s+(\S+)\s+:.*COMMAND=(.+)"
)

# Patrón para líneas de acceso de nginx/apache (Combined Log Format)
ACCESS_LOG_PATTERN = re.compile(
    r'^([\d.]+)\s+-\s+(\S+)\s+\[.*?\]\s+"(\S+)\s+(\S+)\s+\S+"\s+(\d+)\s+(\d+)'
)


def parse_auth_line(line, source_system):
    """Parsea una línea de auth.log y devuelve un evento estructurado."""
    match = AUTH_PATTERN.match(line)
    if not match:
        return None

    timestamp_str, hostname, service, message = match.groups()
    now = datetime.now(timezone.utc)

    # Base del evento
    event = {
        "source_system": source_system,
        "hostname": hostname,
        "service": service,
        "message": message,
        "raw_line": line.strip(),
    }

    # Detectar login SSH fallido
    ssh_fail = SSH_FAILED_PATTERN.search(message)
    if ssh_fail:
        event["event_type"] = "login_failed"
        event["username"] = ssh_fail.group(1)
        event["source_ip"] = ssh_fail.group(2)
        return event

    # Detectar login SSH exitoso
    ssh_ok = SSH_SUCCESS_PATTERN.search(message)
    if ssh_ok:
        event["event_type"] = "login_success"
        event["username"] = ssh_ok.group(1)
        event["source_ip"] = ssh_ok.group(2)
        return event

    # Detectar uso de sudo
    sudo_match = SUDO_PATTERN.search(message)
    if sudo_match:
        event["event_type"] = "sudo_command"
        event["username"] = sudo_match.group(1)
        event["command"] = sudo_match.group(2).strip()
        return event

    # Evento genérico de auth.log
    event["event_type"] = "auth_event"
    return event


def parse_access_line(line, source_system):
    """Parsea una línea de access.log (nginx/apache) en formato Combined."""
    match = ACCESS_LOG_PATTERN.match(line)
    if not match:
        return None

    ip, user, method, path, status, size = match.groups()

    return {
        "source_system": source_system,
        "event_type": "web_access",
        "source_ip": ip,
        "username": user if user != "-" else None,
        "method": method,
        "path": path,
        "status_code": int(status),
        "response_size": int(size),
        "raw_line": line.strip(),
    }


def parse_syslog_line(line, source_system):
    """Parsea una línea genérica de syslog."""
    match = AUTH_PATTERN.match(line)
    if not match:
        return None

    timestamp_str, hostname, service, message = match.groups()

    return {
        "source_system": source_system,
        "event_type": "syslog_event",
        "hostname": hostname,
        "service": service,
        "message": message,
        "raw_line": line.strip(),
    }


def parse_line(line, source_system):
    """Selecciona el parser correcto según el tipo de fuente."""
    if source_system == "ssh":
        return parse_auth_line(line, source_system)
    elif source_system in ("nginx", "apache"):
        return parse_access_line(line, source_system)
    elif source_system == "linux_syslog":
        return parse_syslog_line(line, source_system)
    else:
        return {
            "source_system": source_system,
            "event_type": "generic_event",
            "message": line.strip(),
            "raw_line": line.strip(),
        }


# ─────────────────────────────────────────────────────────────
# LECTURA DE NUEVAS LÍNEAS (como un "tail -f")
# ─────────────────────────────────────────────────────────────

def read_new_lines(filepath, state):
    """
    Lee las líneas nuevas de un fichero desde la última posición conocida.
    Funciona como un tail -f: recuerda dónde se quedó.
    """
    if not os.path.exists(filepath):
        return []

    # Posición anterior (o 0 si es la primera vez)
    last_pos = state.get(filepath, 0)

    # Si el fichero se ha rotado (es más pequeño que antes), empezar de 0
    file_size = os.path.getsize(filepath)
    if file_size < last_pos:
        last_pos = 0

    lines = []
    try:
        with open(filepath, "r", errors="replace") as f:
            f.seek(last_pos)
            lines = f.readlines()
            state[filepath] = f.tell()  # guardar nueva posición
    except PermissionError:
        print(f"[WARN] Sin permisos para leer {filepath}")
    except Exception as e:
        print(f"[ERROR] Leyendo {filepath}: {e}")

    return lines


# ─────────────────────────────────────────────────────────────
# HEARTBEAT — notifica al servidor que el agente está activo
# ─────────────────────────────────────────────────────────────

def get_base_url():
    """Deriva la URL base (scheme + host) desde LOGSENTINEL_URL."""
    parsed = urlparse(LOGSENTINEL_URL)
    return f"{parsed.scheme}://{parsed.netloc}"


def send_heartbeat():
    """Llama a POST /api/systems/heartbeat para marcar el agente como activo."""
    url = get_base_url() + "/api/systems/heartbeat"
    try:
        r = requests.post(url, headers={"X-API-Key": API_KEY}, timeout=5)
        if r.status_code != 200:
            print(f"[WARN] Heartbeat respondió {r.status_code}: {r.text}")
    except requests.exceptions.ConnectionError:
        print(f"[ERROR] No se puede conectar para heartbeat: {url}")
    except Exception as e:
        print(f"[ERROR] Heartbeat: {e}")


# ─────────────────────────────────────────────────────────────
# ENVÍO DE EVENTOS AL LOGCOLLECTOR
# ─────────────────────────────────────────────────────────────

def send_events(events):
    """Envía una lista de eventos al LogCollector."""
    if not events:
        return

    headers = {"Content-Type": "application/json"}
    if API_KEY:
        headers["X-API-Key"] = API_KEY

    for event in events:
        # Añadimos metadatos del agente
        event["agent_system_name"] = SYSTEM_NAME
        event["agent_timestamp"] = datetime.now(timezone.utc).isoformat()

        try:
            r = requests.post(LOGSENTINEL_URL, json=event, headers=headers, timeout=5)
            if r.status_code != 200:
                print(f"[WARN] LogCollector respondió {r.status_code}")
        except requests.exceptions.ConnectionError:
            print(f"[ERROR] No se puede conectar con {LOGSENTINEL_URL}")
            break  # no seguir intentando si no hay conexión
        except Exception as e:
            print(f"[ERROR] Enviando evento: {e}")


# ─────────────────────────────────────────────────────────────
# BUCLE PRINCIPAL
# ─────────────────────────────────────────────────────────────

running = True

def handle_signal(signum, frame):
    """Para parar limpiamente con Ctrl+C o systemctl stop."""
    global running
    print("\n[LogSentinel Agent] Parando...")
    running = False

signal.signal(signal.SIGTERM, handle_signal)
signal.signal(signal.SIGINT, handle_signal)


def main():
    load_config()
    state = load_state()

    print(f"[LogSentinel Agent] Iniciado")
    print(f"  → URL:     {LOGSENTINEL_URL}")
    print(f"  → Sistema: {SYSTEM_NAME}")
    print(f"  → Intervalo: {SEND_INTERVAL}s")

    # Heartbeat inicial al arrancar
    send_heartbeat()
    last_heartbeat = time.time()

    while running:
        # Heartbeat cada 60 segundos
        if time.time() - last_heartbeat >= 60:
            send_heartbeat()
            last_heartbeat = time.time()

        all_events = []

        for source in LOG_SOURCES:
            filepath = source["path"]
            source_system = source["source_system"]

            # Leer líneas nuevas
            new_lines = read_new_lines(filepath, state)

            # Parsear cada línea
            for line in new_lines:
                line = line.strip()
                if not line:
                    continue
                event = parse_line(line, source_system)
                if event:
                    all_events.append(event)

        # Enviar todo al LogCollector
        if all_events:
            print(f"[LogSentinel Agent] Enviando {len(all_events)} eventos...")
            send_events(all_events)

        # Guardar estado (posiciones de lectura)
        save_state(state)

        # Esperar antes del siguiente ciclo
        time.sleep(SEND_INTERVAL)

    # Al salir, guardar estado
    save_state(state)
    print("[LogSentinel Agent] Parado correctamente.")


if __name__ == "__main__":
    main()
