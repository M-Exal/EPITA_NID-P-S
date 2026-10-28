"""
Backend Flask pour le Dashboard SIEM CyBear.
Fournit une interface web temps réel et des endpoints API / SSE
pour la supervision des alertes NIDS / NIPS.
Inclut également le Panneau d'Attaque (pentest automatisé).
"""

import json
import os
import re
import subprocess
import sys
import threading
import time
import uuid
from collections import defaultdict, Counter
from datetime import datetime
from zoneinfo import ZoneInfo

import paramiko
from cryptography.hazmat.primitives import hashes
from flask import Flask, Response, jsonify, render_template, request
from flask_socketio import SocketIO, emit

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("FLASK_SECRET", "cybear-ssh-secret")
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

# Tokens SSH en attente : token → {utilisateur, mot_de_passe, target, port}
_ssh_pending: dict = {}
# Sessions SSH actives : socket_sid → {client, channel}
_ssh_actifs: dict = {}

# Patch de compatibilité RSA pour Metasploitable 2 (clé ssh-rsa/SHA-1 dépréciée)
try:
    from paramiko.transport import Transport
    from paramiko.rsakey import RSAKey
    RSAKey.HASHES["ssh-rsa"] = hashes.SHA1
    Transport._key_info["ssh-rsa"] = RSAKey
    if "ssh-rsa" not in Transport._preferred_keys:
        Transport._preferred_keys = Transport._preferred_keys + ("ssh-rsa",)
except Exception:
    pass

# Fuseau horaire de référence pour tous les horodatages ISO (conteneurs en UTC)
TZ_PARIS = ZoneInfo("Europe/Paris")

# Fichier source des alertes JSON
DEFAULT_JSON = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "data", "nids", "nids_alerts.json")
)
ALERT_JSON_PATH = os.getenv("NIDS_ALERT_JSON", DEFAULT_JSON)

# Classification des sévérités
SEVERITE_MAP = {
    "DOS": "CRITIQUE",
    "BRUTE_FORCE": "CRITIQUE",
    "SQL_INJECTION": "CRITIQUE",
    "NULL_SCAN": "HAUTE",
    "XMAS_SCAN": "HAUTE",
    "XSS": "HAUTE",
    "PATH_TRAVERSAL": "HAUTE",
    "SCAN_PORTS": "MOYENNE",
}

TYPES_ATTAQUES = [
    "SCAN_PORTS",
    "XMAS_SCAN",
    "NULL_SCAN",
    "BRUTE_FORCE",
    "DOS",
    "SQL_INJECTION",
    "XSS",
    "PATH_TRAVERSAL",
]


def lire_alertes():
    """Lit et parse de façon sécurisée le fichier d'alertes NIDS."""
    if not os.path.exists(ALERT_JSON_PATH):
        return []
    try:
        with open(ALERT_JSON_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, list):
                return data
            return []
    except Exception:
        # Fichier en cours d'écriture ou syntaxe JSON incomplète
        return []


def calculer_statistiques(alertes):
    """Calcule les indicateurs clés et agrégations pour le SIEM."""
    total = len(alertes)
    by_type = Counter()
    by_ip = Counter()
    severity_counts = {"CRITIQUE": 0, "HAUTE": 0, "MOYENNE": 0}
    matrix = defaultdict(lambda: defaultdict(int))
    timeline_dict = defaultdict(lambda: {"CRITIQUE": 0, "HAUTE": 0, "MOYENNE": 0, "total": 0})

    for a in alertes:
        atype = a.get("type", "INCONNU")
        ip = a.get("src_ip", "0.0.0.0")
        sev = SEVERITE_MAP.get(atype, "MOYENNE")

        by_type[atype] += 1
        by_ip[ip] += 1
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        matrix[ip][atype] += 1

        # Timeline par minute (ex: "14:32")
        ts = a.get("timestamp", "")
        minute_key = "Recent"
        if len(ts) >= 16:
            # Format ISO "2026-10-19T09:43:27" -> "09:43"
            minute_key = ts[11:16]
        timeline_dict[minute_key]["total"] += 1
        timeline_dict[minute_key][sev] += 1

    # Formatage de la timeline chronologique
    timeline = []
    for k in sorted(timeline_dict.keys())[-30:]:
        timeline.append({
            "minute": k,
            "total": timeline_dict[k]["total"],
            "critique": timeline_dict[k]["CRITIQUE"],
            "haute": timeline_dict[k]["HAUTE"],
            "moyenne": timeline_dict[k]["MOYENNE"],
        })

    # Conversion de la matrice en structure sérialisable
    matrix_serializable = {}
    for ip, atks in matrix.items():
        matrix_serializable[ip] = dict(atks)

    derniere_alerte = alertes[-1] if alertes else None

    return {
        "total_alerts": total,
        "unique_ips": len(by_ip),
        "alerts_by_type": dict(by_type),
        "alerts_by_ip": sorted(by_ip.items(), key=lambda x: x[1], reverse=True)[:10],
        "severity_counts": severity_counts,
        "latest_alerts": list(reversed(alertes[-50:])),
        "attack_matrix": matrix_serializable,
        "timeline": timeline,
        "derniere_alerte": derniere_alerte,
    }


@app.route("/")
def index():
    """Affiche l'interface du Dashboard SIEM."""
    return render_template("index.html")


@app.route("/api/alerts")
def api_alerts():
    """Retourne la liste brute de toutes les alertes."""
    return jsonify(lire_alertes())


@app.route("/api/stats")
def api_stats():
    """Retourne la synthèse analytique complète."""
    alertes = lire_alertes()
    return jsonify(calculer_statistiques(alertes))


@app.route("/api/stream")
def api_stream():
    """Flux SSE (Server-Sent Events) pour diffuser les alertes en direct."""
    def event_stream():
        derniers_count = -1

        while True:
            try:
                alertes = lire_alertes()
                count = len(alertes)

                # Émission immédiate au premier branchement ou lors d'une nouveauté
                if count != derniers_count:
                    derniers_count = count
                    stats = calculer_statistiques(alertes)
                    payload = {
                        "type": "update",
                        "total": count,
                        "stats": stats,
                        "nouveau": alertes[-5:] if count > 0 else [],
                    }
                    yield f"data: {json.dumps(payload)}\n\n"
                else:
                    # Heartbeat pour garder la connexion active
                    yield f": heartbeat {int(time.time())}\n\n"

            except Exception as e:
                yield f"data: {json.dumps({'type': 'error', 'message': str(e)})}\n\n"

            time.sleep(1.5)

    response = Response(event_stream(), mimetype="text/event-stream")
    response.headers["Cache-Control"] = "no-cache"
    response.headers["X-Accel-Buffering"] = "no"
    response.headers["Connection"] = "keep-alive"
    return response


# ===========================================================================
# Panneau d'Attaque — gestion des processus de pentest
# ===========================================================================

def determiner_scripts_dir() -> str:
    """Détermine dynamiquement le chemin absolu du dossier scripts/."""
    if "SCRIPTS_DIR" in os.environ and os.path.isdir(os.environ["SCRIPTS_DIR"]):
        return os.path.abspath(os.environ["SCRIPTS_DIR"])
    candidats = [
        os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "scripts")),
        os.path.abspath(os.path.join(os.path.dirname(__file__), "scripts")),
        "/app/scripts",
    ]
    for c in candidats:
        if os.path.isdir(c):
            return c
    return candidats[0]


SCRIPTS_DIR = determiner_scripts_dir()

# Registre des attaques disponibles : nom_clé -> fichier script
ATTAQUES_DISPONIBLES = {
    "all_attacks": "run_all_attacks.py",
    "scan_ports": "run_scan_ports.py",
    "xmas_scan": "run_xmas_scan.py",
    "null_scan": "run_null_scan.py",
    "brute_force_ssh": "run_brute_force_ssh.py",
}

# État en mémoire des attaques lancées
# { nom_attaque: {"pid": int, "log": str, "status": "en_cours"|"terminee", "debut": str} }
_attaques_en_cours: dict = {}
_attaques_terminees: list = []


def _nettoyer_terminees():
    """Déplace dans _attaques_terminees les processus qui ont fini."""
    finies = []
    for nom, info in list(_attaques_en_cours.items()):
        proc: subprocess.Popen = info.get("proc")
        if proc and proc.poll() is not None:
            finies.append(nom)
            _attaques_terminees.append({
                "attaque": nom,
                "debut": info["debut"],
                "fin": datetime.now(TZ_PARIS).isoformat(timespec="seconds"),
                "code_retour": proc.returncode,
                "log": info["log"],
            })
    for nom in finies:
        del _attaques_en_cours[nom]


@app.route("/attaques")
def panneau_attaques():
    """Affiche le Panneau d'Attaques CyBear Pentest."""
    return render_template("attack_panel.html")


@app.route("/api/attaques/lancer", methods=["POST"])
def api_lancer_attaque():
    """Lance une attaque en background via subprocess.

    Corps JSON attendu : {"attaque": "brute_force_ssh"}
    Retourne : {"status": "started", "attaque": "...", "log": "..."}
    """
    _nettoyer_terminees()

    data = request.get_json(silent=True) or {}
    nom = data.get("attaque", "").strip()

    if not nom:
        return jsonify({"error": "Paramètre 'attaque' manquant"}), 400

    if nom not in ATTAQUES_DISPONIBLES:
        return jsonify({
            "error": f"Attaque '{nom}' non implémentée",
            "disponibles": list(ATTAQUES_DISPONIBLES.keys()),
        }), 400

    if nom in _attaques_en_cours:
        return jsonify({
            "error": f"L'attaque '{nom}' est déjà en cours",
            "status": "already_running",
        }), 409

    scripts_dir = determiner_scripts_dir()
    script_file = ATTAQUES_DISPONIBLES[nom]
    script_path = os.path.join(scripts_dir, script_file)

    if not os.path.isfile(script_path):
        return jsonify({
            "error": f"Fichier script introuvable : {script_path}",
            "scripts_dir": scripts_dir,
        }), 500

    timestamp = int(time.time())
    log_path = f"/tmp/attack_{nom}_{timestamp}.log"

    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    pentest_dir = os.path.join(repo_root, "pentest")
    nouveau_pythonpath = os.pathsep.join(filter(None, [
        repo_root,
        pentest_dir,
        "/app",
        "/app/pentest",
        os.environ.get("PYTHONPATH", ""),
    ]))
    env = {
        **os.environ,
        "PYTHONUNBUFFERED": "1",
        "PYTHONPATH": nouveau_pythonpath,
        "PENTEST_DATA_DIR": "/tmp",
    }

    try:
        with open(log_path, "w", encoding="utf-8") as log_file:
            proc = subprocess.Popen(
                [sys.executable, "-u", script_path],
                stdout=log_file,
                stderr=subprocess.STDOUT,
                env=env,
            )
    except Exception as exc:
        return jsonify({"error": f"Impossible de démarrer le subprocess : {exc}"}), 500

    _attaques_en_cours[nom] = {
        "proc": proc,
        "log": log_path,
        "debut": datetime.now(TZ_PARIS).isoformat(timespec="seconds"),
        "status": "en_cours",
    }

    return jsonify({
        "status": "started",
        "attaque": nom,
        "log": log_path,
        "pid": proc.pid,
    })


def _recuperer_acces_valides() -> list:
    """Tente de lire les accès valides découverts lors du brute-force SSH."""
    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    candidats = [
        "/app/data/pentest/pentest_results.json",
        "/app/data/pentest_results.json",
        "/tmp/pentest_results.json",
        os.path.join(repo_root, "data", "pentest", "pentest_results.json"),
        os.path.join(repo_root, "data", "pentest_results.json"),
    ]
    for chemin in candidats:
        if os.path.isfile(chemin):
            try:
                with open(chemin, "r", encoding="utf-8") as f:
                    data = json.load(f)
                acces = data.get("attaques", {}).get("brute_force_ssh", {}).get("acces_valides", [])
                if acces:
                    return acces
            except Exception:
                pass

    # Analyse des logs récents (attaques en cours et terminées)
    sources = list(_attaques_en_cours.values()) + list(reversed(_attaques_terminees))
    for item in sources:
        log_path = item.get("log")
        if log_path and os.path.isfile(log_path):
            try:
                with open(log_path, "r", encoding="utf-8", errors="replace") as f:
                    contenu = f.read()
                import re
                matches = re.findall(
                    r"\[\+\]\s+([a-zA-Z0-9_\-]+):([^\s—]+)\s+—\s+authentification réussie",
                    contenu,
                )
                if matches:
                    vus = set()
                    res = []
                    for u, p in matches:
                        if (u, p) not in vus:
                            vus.add((u, p))
                            res.append({"utilisateur": u, "mot_de_passe": p, "whoami": u})
                    return res
            except Exception:
                pass
    return []


@app.route("/api/attaques/ssh_connect", methods=["POST"])
def api_ssh_connect():
    """Crée un token de session SSH et retourne l'URL du terminal."""
    data = request.get_json(silent=True) or {}
    user = data.get("utilisateur", "msfadmin")
    password = data.get("mot_de_passe", "")
    target = os.getenv("TARGET_HOST", "metasploitable")
    port = int(os.getenv("SSH_PORT", "22"))

    token = str(uuid.uuid4())
    _ssh_pending[token] = {
        "utilisateur": user,
        "mot_de_passe": password,
        "target": target,
        "port": port,
    }

    return jsonify({
        "status": "ready",
        "token": token,
        "utilisateur": user,
        "cible": f"{target}:{port}",
    })


@app.route("/terminal")
def terminal():
    """Page du terminal SSH interactif (xterm.js)."""
    return render_template("terminal.html")


# ── WebSocket : terminal SSH ──────────────────────────────────────────────────

@socketio.on("join_session")
def ws_join_session(data):
    """Ouvre la connexion SSH et démarre le forwarding stdout → WebSocket."""
    token = data.get("token", "")
    session = _ssh_pending.pop(token, None)
    if not session:
        emit("terminal_output", {
            "data": "\r\n\x1b[31m[Erreur] Session expirée ou token invalide.\x1b[0m\r\n"
        })
        return

    utilisateur = session["utilisateur"]
    mot_de_passe = session["mot_de_passe"]
    target = session["target"]
    port = session["port"]
    sid = request.sid

    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            hostname=target,
            port=port,
            username=utilisateur,
            password=mot_de_passe,
            timeout=10.0,
            banner_timeout=10.0,
            auth_timeout=10.0,
            allow_agent=False,
            look_for_keys=False,
        )

        channel = client.invoke_shell(term="xterm-256color", width=220, height=50)
        channel.setblocking(False)

        _ssh_actifs[sid] = {"client": client, "channel": channel}

        emit("terminal_connected", {
            "utilisateur": utilisateur,
            "target": target,
            "port": port,
        })

        def _lire_sortie():
            """Thread : lit le canal SSH et relaie vers le WebSocket."""
            while sid in _ssh_actifs:
                try:
                    if channel.recv_ready():
                        bloc = channel.recv(4096)
                        if bloc:
                            socketio.emit(
                                "terminal_output",
                                {"data": bloc.decode("utf-8", errors="replace")},
                                room=sid,
                            )
                    if channel.closed or channel.exit_status_ready():
                        socketio.emit(
                            "terminal_output",
                            {"data": "\r\n\x1b[33m[Session fermée]\x1b[0m\r\n"},
                            room=sid,
                        )
                        _ssh_actifs.pop(sid, None)
                        break
                    time.sleep(0.03)
                except Exception:
                    break

        t = threading.Thread(target=_lire_sortie, daemon=True)
        t.start()
        _ssh_actifs[sid]["thread"] = t

    except paramiko.AuthenticationException:
        emit("terminal_output", {
            "data": f"\r\n\x1b[31m[Erreur] Authentification refusée pour {utilisateur}.\x1b[0m\r\n"
        })
        emit("terminal_error", {"message": f"Authentification refusée pour {utilisateur}"})
    except Exception as exc:
        emit("terminal_output", {
            "data": f"\r\n\x1b[31m[Erreur] {exc}\x1b[0m\r\n"
        })
        emit("terminal_error", {"message": str(exc)})


@socketio.on("terminal_input")
def ws_terminal_input(data):
    """Reçoit la saisie du terminal et l'envoie au canal SSH."""
    session = _ssh_actifs.get(request.sid)
    if session:
        try:
            session["channel"].send(data.get("data", ""))
        except Exception:
            pass


@socketio.on("terminal_resize")
def ws_terminal_resize(data):
    """Redimensionne le PTY SSH selon la taille du terminal xterm.js."""
    session = _ssh_actifs.get(request.sid)
    if session:
        try:
            session["channel"].resize_pty(
                width=int(data.get("cols", 80)),
                height=int(data.get("rows", 24)),
            )
        except Exception:
            pass


@socketio.on("disconnect")
def ws_disconnect():
    """Ferme proprement la session SSH à la déconnexion WebSocket."""
    session = _ssh_actifs.pop(request.sid, None)
    if session:
        try:
            session["channel"].close()
            session["client"].close()
        except Exception:
            pass


@app.route("/api/attaques/status")
def api_status_attaques():
    """Retourne l'état de toutes les attaques (en cours + terminées) et les accès valides."""
    _nettoyer_terminees()

    en_cours = []
    for nom, info in _attaques_en_cours.items():
        # Lecture des dernières lignes du log
        log_extrait = _lire_log(info["log"])
        en_cours.append({
            "attaque": nom,
            "debut": info["debut"],
            "log_extrait": log_extrait,
        })

    # Inclut l'extrait du log pour chaque attaque terminée
    terminees = []
    for t in _attaques_terminees[-20:]:
        t_data = dict(t)
        t_data["log_extrait"] = _lire_log(t.get("log", ""))
        terminees.append(t_data)

    return jsonify({
        "en_cours": en_cours,
        "terminees": terminees,
        "acces_valides": _recuperer_acces_valides(),
    })


def _lire_log(path: str, nb_lignes: int = 50) -> str:
    """Retourne les dernières lignes d'un fichier log d'attaque."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            lignes = f.readlines()
        return "".join(lignes[-nb_lignes:])
    except Exception:
        return ""


if __name__ == "__main__":
    port = int(os.getenv("PORT", "5050"))
    socketio.run(app, host="0.0.0.0", port=port, debug=False, allow_unsafe_werkzeug=True)
