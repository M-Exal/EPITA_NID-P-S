"""
Backend Flask pour le Dashboard SIEM CyBear.
Fournit une interface web temps réel et des endpoints API / SSE
pour la supervision des alertes NIDS / NIPS.
Inclut également le Panneau d'Attaque (pentest automatisé).
"""

import json
import os
import subprocess
import sys
import time
from collections import defaultdict, Counter
from datetime import datetime
from flask import Flask, Response, jsonify, render_template, request

app = Flask(__name__)

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
        derniere_taille = -1
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

# Répertoire contenant les scripts d'attaque standalone
SCRIPTS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "scripts"))

# Registre des attaques disponibles : nom_clé -> fichier script
ATTAQUES_DISPONIBLES = {
    "brute_force_ssh": "run_brute_force_ssh.py",
}

# État en mémoire des attaques lancées
# { nom_attaque: {"pid": int, "log": str, "status": "en_cours"|"terminee", "debut": str} }
_attaques_en_cours: dict = {}
_attaques_terminees: list = []


def _nettoyer_terminees():
    """Déplace dans _attaques_terminees les processus qui ont fini."""
    global _attaques_en_cours, _attaques_terminees
    finies = []
    for nom, info in list(_attaques_en_cours.items()):
        proc: subprocess.Popen = info.get("proc")
        if proc and proc.poll() is not None:
            finies.append(nom)
            _attaques_terminees.append({
                "attaque": nom,
                "debut": info["debut"],
                "fin": datetime.now().isoformat(timespec="seconds"),
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

    script_path = os.path.join(SCRIPTS_DIR, ATTAQUES_DISPONIBLES[nom])
    timestamp = int(time.time())
    log_path = f"/tmp/attack_{nom}_{timestamp}.log"

    try:
        log_file = open(log_path, "w", encoding="utf-8")  # noqa: WPS515
        proc = subprocess.Popen(
            [sys.executable, script_path],
            stdout=log_file,
            stderr=subprocess.STDOUT,
            env={**os.environ},
        )
    except Exception as exc:
        return jsonify({"error": f"Impossible de démarrer le subprocess : {exc}"}), 500

    _attaques_en_cours[nom] = {
        "proc": proc,
        "log": log_path,
        "debut": datetime.now().isoformat(timespec="seconds"),
        "status": "en_cours",
    }

    return jsonify({
        "status": "started",
        "attaque": nom,
        "log": log_path,
        "pid": proc.pid,
    })


@app.route("/api/attaques/status")
def api_status_attaques():
    """Retourne l'état de toutes les attaques (en cours + terminées)."""
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

    return jsonify({
        "en_cours": en_cours,
        "terminees": _attaques_terminees[-20:],  # 20 dernières
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
    app.run(host="0.0.0.0", port=port, debug=False, threaded=True)
