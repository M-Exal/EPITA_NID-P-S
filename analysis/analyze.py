#!/usr/bin/env python3
"""
analyze.py — Récupération et analyse des données du honeypot Cowrie.

Cowrie journalise chaque évènement au format JSON (une ligne = un évènement)
dans var/log/cowrie/cowrie.json. Ce module :
  1. récupère ces données (fetch_honeypot_data) ;
  2. les charge dans un DataFrame pandas ;
  3. identifie les tentatives d'attaque (IP les plus actives, identifiants
     testés, commandes exécutées, types d'évènements) ;
  4. génère des graphiques (matplotlib) et un rapport texte.

Usage :
    python3 analyze.py --log ../data/cowrie/log/cowrie.json
    python3 analyze.py --log cowrie.json --out ../data/analysis
"""

import argparse
import json
import os

import pandas as pd

# Backend non interactif : on génère des PNG sans serveur graphique (Docker).
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402


def fetch_honeypot_data(chemin_log):
    """
    Récupère les données du honeypot depuis son journal JSON.

    Cowrie écrit un objet JSON par ligne (format JSON Lines). On tolère les
    lignes corrompues (fichier en cours d'écriture) sans planter.

    :param chemin_log: chemin du fichier cowrie.json.
    :return: liste de dictionnaires (évènements). Contient toujours la clé
             attendue par les tests même si le fichier est vide.
    """
    evenements = []
    if not os.path.exists(chemin_log):
        print(f"[ANALYSE] Journal introuvable : {chemin_log}")
        return {"attacks": [], "evenements": []}

    with open(chemin_log, "r", encoding="utf-8", errors="ignore") as f:
        for ligne in f:
            ligne = ligne.strip()
            if not ligne:
                continue
            try:
                evenements.append(json.loads(ligne))
            except json.JSONDecodeError:
                continue  # ligne partielle : on l'ignore

    print(f"[ANALYSE] {len(evenements)} évènements récupérés.")
    # On expose "attacks" (évènements de connexion/login) pour l'analyse.
    attaques = [e for e in evenements
                if str(e.get("eventid", "")).startswith(
                    ("cowrie.login", "cowrie.command", "cowrie.session"))]
    return {"attacks": attaques, "evenements": evenements}


def charger_dataframe(evenements):
    """Transforme la liste d'évènements en DataFrame pandas."""
    if not evenements:
        return pd.DataFrame()
    return pd.json_normalize(evenements)


def analyser(df):
    """
    Produit les statistiques clés à partir du DataFrame.

    :return: dictionnaire de résultats (séries pandas).
    """
    resultats = {}
    if df.empty:
        return resultats

    # Types d'évènements les plus fréquents.
    if "eventid" in df.columns:
        resultats["types_evenements"] = df["eventid"].value_counts()

    # Adresses IP sources les plus actives.
    if "src_ip" in df.columns:
        resultats["ip_actives"] = df["src_ip"].value_counts().head(10)

    # Identifiants testés lors des tentatives de connexion.
    logins = df[df.get("eventid", "").astype(str).str.startswith("cowrie.login")] \
        if "eventid" in df.columns else pd.DataFrame()
    if not logins.empty:
        if "username" in logins.columns:
            resultats["usernames"] = logins["username"].value_counts().head(10)
        if "password" in logins.columns:
            resultats["passwords"] = logins["password"].value_counts().head(10)
        # Taux de succès / échec du brute-force.
        resultats["login_resultats"] = logins["eventid"].value_counts()

    # Commandes saisies par l'attaquant après connexion.
    if "eventid" in df.columns and "input" in df.columns:
        commandes = df[df["eventid"] == "cowrie.command.input"]["input"]
        if not commandes.empty:
            resultats["commandes"] = commandes.value_counts().head(10)

    return resultats


def generer_graphiques(resultats, dossier_sortie):
    """Génère des graphiques PNG à partir des résultats d'analyse."""
    os.makedirs(dossier_sortie, exist_ok=True)
    fichiers = []

    def _barres(serie, titre, nom_fichier, couleur="#c0392b"):
        if serie is None or serie.empty:
            return
        plt.figure(figsize=(10, 5))
        serie.sort_values().plot(kind="barh", color=couleur)
        plt.title(titre)
        plt.tight_layout()
        chemin = os.path.join(dossier_sortie, nom_fichier)
        plt.savefig(chemin, dpi=120)
        plt.close()
        fichiers.append(chemin)
        print(f"[ANALYSE] Graphique généré : {chemin}")

    _barres(resultats.get("ip_actives"),
            "Top 10 des IP sources les plus actives", "top_ip.png")
    _barres(resultats.get("usernames"),
            "Top 10 des identifiants testés", "top_usernames.png", "#2980b9")
    _barres(resultats.get("passwords"),
            "Top 10 des mots de passe testés", "top_passwords.png", "#8e44ad")
    _barres(resultats.get("types_evenements"),
            "Répartition des types d'évènements", "types_evenements.png", "#27ae60")
    return fichiers


def generer_rapport(resultats, chemin_rapport):
    """Écrit un rapport texte lisible des résultats d'analyse."""
    lignes = ["===== RAPPORT D'ANALYSE DU HONEYPOT COWRIE =====", ""]
    if not resultats:
        lignes.append("Aucune donnée à analyser "
                      "(le honeypot n'a pas encore reçu de trafic).")
    else:
        for titre, cle in [("Types d'évènements", "types_evenements"),
                           ("IP les plus actives", "ip_actives"),
                           ("Identifiants testés", "usernames"),
                           ("Mots de passe testés", "passwords"),
                           ("Résultats des connexions", "login_resultats"),
                           ("Commandes exécutées", "commandes")]:
            serie = resultats.get(cle)
            if serie is not None and not serie.empty:
                lignes.append(f"\n--- {titre} ---")
                for index, valeur in serie.items():
                    lignes.append(f"  {index} : {valeur}")

    rapport = "\n".join(lignes)
    os.makedirs(os.path.dirname(chemin_rapport) or ".", exist_ok=True)
    with open(chemin_rapport, "w", encoding="utf-8") as f:
        f.write(rapport)
    print(f"[ANALYSE] Rapport écrit : {chemin_rapport}")
    return rapport


def main():
    parser = argparse.ArgumentParser(description="Analyse des logs du honeypot Cowrie.")
    parser.add_argument("--log", default="../data/cowrie/log/cowrie.json",
                        help="Chemin du journal cowrie.json.")
    parser.add_argument("--out", default="../data/analysis",
                        help="Dossier de sortie (graphiques + rapport).")
    args = parser.parse_args()

    donnees = fetch_honeypot_data(args.log)
    df = charger_dataframe(donnees["evenements"])
    resultats = analyser(df)
    generer_graphiques(resultats, args.out)
    rapport = generer_rapport(resultats, os.path.join(args.out, "rapport_analyse.txt"))
    print("\n" + rapport)


if __name__ == "__main__":
    main()
