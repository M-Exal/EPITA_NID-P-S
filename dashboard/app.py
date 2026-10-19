"""
Backend Flask pour le Dashboard SIEM CyBear.
Fournit une interface web temps réel et des endpoints API / SSE
pour la supervision des alertes NIDS / NIPS.
"""

import json
import os
import time
from collections import defaultdict, Counter
from datetime import datetime
from flask import Flask, Response, jsonify, render_template

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


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)
