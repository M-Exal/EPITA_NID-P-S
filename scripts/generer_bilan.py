#!/usr/bin/env python3
"""
generer_bilan.py — Génère le PDF du bilan intermédiaire (Séance 2).

Le livrable exigé pour le 27 novembre 2026 reprend les points imposés par le
sujet : membres du groupe, honeypot sélectionné, attaques prévues, répartition
des tâches, planning prévisionnel, outils utilisés, état d'avancement du code
et des tests, travaux prévus pour la session du 15 décembre.

Usage :
    python3 scripts/generer_bilan.py          # écrit docs/bilan_seance2.pdf
"""

import os

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (Paragraph, SimpleDocTemplate, Spacer, Table,
                                TableStyle)

RACINE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SORTIE = os.path.join(RACINE, "docs", "bilan_seance2.pdf")

# ---------------------------------------------------------------------- #
# Données du bilan (à mettre à jour au fil des séances puis relancer).
# ---------------------------------------------------------------------- #
MEMBRES = [
    ["Maximilien", "Chef de projet / développement NIDS",
     "coordination, moteur de détection, alertes, intégration Docker"],
    ["Antoine", "Développeur Python",
     "script de pentest automatisé, tests unitaires"],
    ["Alexis", "Analyste de données",
     "récupération et analyse des logs Cowrie, graphiques"],
    ["Léa Bonet", "Rapport et soutenance",
     "documentation, diaporama, vidéo, rapport chiffré"],
]

ATTAQUES = [
    ["Scan de ports", "découverte des services ouverts (nmap, repli socket Python)"],
    ["Scan SYN furtif", "demi-connexion half-open avec Scapy"],
    ["Brute-force SSH", "attaque par dictionnaire avec paramiko (combinaisons faibles)"],
    ["Déni de service", "inondation de connexions contrôlée (volume limité au labo)"],
    ["Injection SQL", "envoi de payloads SQLi en clair pour éprouver les signatures du NIDS"],
]

PLANNING = [
    ["Séance 1", "Lancement et organisation",
     "présentation du sujet, répartition des rôles, recherche documentaire "
     "(honeypots, NIDS, Scapy)"],
    ["Séance 2 — 27/11/2026", "Bilan intermédiaire (ce document)",
     "membres, honeypot retenu, attaques prévues, planning, état d'avancement"],
    ["Séance 3", "Script, tests et analyse",
     "finalisation du pentest, récupération et analyse des données, début du NIDS"],
    ["Séance 4", "Finalisation du projet",
     "détection complète, alertes et rapport chiffré, tests et réglage des seuils, "
     "rédaction du rapport"],
    ["Session du 15/12/2026", "Préparation de la soutenance",
     "démonstration complète, rapport, diaporama et vidéo"],
    ["Séance 5", "Soutenance orale",
     "présentation de 15 minutes puis session de questions"],
]

OUTILS = [
    ["IDE et édition", "PyCharm, Visual Studio Code, Vim / terminal"],
    ["Bibliothèques Python",
     "Scapy (capture de paquets), paramiko (SSH), pandas et matplotlib "
     "(analyse et graphiques), cryptography / Fernet (chiffrement du rapport), "
     "pytest (tests), bibliothèques standard socket, smtplib, json, logging"],
    ["Conteneurisation", "Docker et Docker Compose (honeypot, NIDS, pentest, analyse)"],
    ["Honeypot", "Cowrie (logiciel libre, SSH et Telnet)"],
    ["Versionnement", "GitHub (dépôt du groupe, branche de développement)"],
    ["Communication", "Discord"],
]

AVANCEMENT = [
    ["Installation du honeypot", "Terminé",
     "Cowrie déployé via Docker Compose, identifiants faibles acceptés "
     "(userdb), journaux JSON vérifiés en condition réelle"],
    ["Script de pentest automatisé", "Terminé",
     "classe Pentester, une méthode par attaque, gestion complète des "
     "exceptions, résultats enregistrés en JSON"],
    ["Récupération des données", "Terminé",
     "lecture du journal cowrie.json (JSON Lines) tolérant aux lignes "
     "tronquées"],
    ["Analyse des données", "Terminé",
     "statistiques pandas (IP actives, identifiants, commandes) et 4 "
     "graphiques générés automatiquement"],
    ["NIDS : capture", "Terminé",
     "Scapy en temps réel, sonde partageant la pile réseau du honeypot, "
     "sauvegarde de la capture en .pcap"],
    ["NIDS : détection et alertes", "Terminé",
     "anomalies (scan, DoS, brute-force) et signatures (SQLi, XSS, "
     "traversal, flags TCP), journaux .log et .json"],
    ["Rapport chiffré par courriel", "Terminé",
     "chiffrement Fernet avant envoi SMTP, déchiffrement côté destinataire"],
    ["Tests", "Terminé",
     "45 tests pytest verts, dont deux scénarios de trafic normal sans "
     "fausse alerte"],
    ["Démonstration de bout en bout", "Terminé",
     "script scripts/demo.sh validé en réel : attaques détectées, honeypot "
     "alimenté, analyses générées"],
    ["Rapport et soutenance", "À faire",
     "diaporama, vidéo de 15 minutes, session de questions"],
]

TRAVAUX_15_DEC = [
    "Lancer la démonstration complète (scripts/demo.sh) et consigner les "
    "résultats pour le rapport : alertes du NIDS, journaux du honeypot, "
    "graphiques d'analyse.",
    "Ajuster les seuils du NIDS selon les logs réels, puis relancer la suite "
    "de tests pour confirmer l'absence de fausses alertes.",
    "Rédiger le rapport : architecture, démonstration, méthodologie de "
    "récupération des données, analyse, résultats et conclusions.",
    "Préparer le diaporama de soutenance (introduction, honeypot, script de "
    "pentest, données, NIDS, conclusions) et répartir la parole entre les "
    "quatre membres.",
    "Enregistrer les séquences vidéo de la démonstration (pentest puis "
    "détections du NIDS).",
]


def construire_styles():
    """Styles du document (titres, tableaux)."""
    base = getSampleStyleSheet()
    styles = {
        "titre": ParagraphStyle("titre", parent=base["Title"],
                                fontSize=18, leading=22, spaceAfter=2 * mm),
        "sous_titre": ParagraphStyle("sous_titre", parent=base["Normal"],
                                     fontSize=11, leading=14,
                                     alignment=TA_CENTER,
                                     textColor=colors.HexColor("#444444"),
                                     spaceAfter=6 * mm),
        "h2": ParagraphStyle("h2", parent=base["Heading2"], fontSize=13,
                             leading=16, spaceBefore=6 * mm, spaceAfter=2 * mm,
                             textColor=colors.HexColor("#1a5276")),
        "p": ParagraphStyle("p", parent=base["Normal"], fontSize=9.5,
                            leading=13, spaceAfter=2 * mm),
        "cellule": ParagraphStyle("cellule", parent=base["Normal"],
                                  fontSize=9, leading=12),
        "cellule_titre": ParagraphStyle("cellule_titre", parent=base["Normal"],
                                        fontSize=9, leading=12,
                                        textColor=colors.white),
    }
    return styles


def tableau(donnees, largeurs, styles, entete=True):
    """Construit un tableau mis en forme (entete coloree, lignes alternees)."""
    style_courant = styles["cellule_titre"] if entete else styles["cellule"]
    lignes = []
    for indice, ligne in enumerate(donnees):
        style = style_courant if (entete and indice == 0) else styles["cellule"]
        lignes.append([Paragraph(str(colonne), style) for colonne in ligne])

    table = Table(lignes, colWidths=largeurs, repeatRows=1 if entete else 0)
    commandes = [
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#b0b0b0")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
    ]
    if entete:
        commandes.append(("BACKGROUND", (0, 0), (-1, 0),
                          colors.HexColor("#1a5276")))
        premier_corps = 1
    else:
        premier_corps = 0
    for indice in range(premier_corps, len(donnees)):
        if (indice - premier_corps) % 2 == 1:
            commandes.append(("BACKGROUND", (0, indice), (-1, indice),
                              colors.HexColor("#eef3f8")))
    table.setStyle(TableStyle(commandes))
    return table


def construire_document():
    """Assemble le contenu du bilan puis écrit le PDF."""
    styles = construire_styles()
    doc = SimpleDocTemplate(
        SORTIE, pagesize=A4,
        leftMargin=18 * mm, rightMargin=18 * mm,
        topMargin=16 * mm, bottomMargin=16 * mm,
        title="Bilan intermediaire - Seance 2",
        author="Groupe projet securite EPITA",
    )
    largeur = doc.width
    elements = []

    elements.append(Paragraph("Bilan intermédiaire - Séance 2", styles["titre"]))
    elements.append(Paragraph(
        "Projet sécurité : honeypot, pentest automatisé et NIDS<br/>"
        "Échéance : 27 novembre 2026 - Groupe de 4 étudiants",
        styles["sous_titre"]))

    # 1. Membres ------------------------------------------------------- #
    elements.append(Paragraph("1. Membres du groupe", styles["h2"]))
    elements.append(tableau(
        [["Membre", "Rôle", "Responsabilités"]] + MEMBRES,
        [28 * mm, 48 * mm, largeur - 76 * mm], styles))

    # 2. Honeypot et attaques ------------------------------------------- #
    elements.append(Paragraph("2. Honeypot sélectionné et attaques prévues",
                              styles["h2"]))
    elements.append(Paragraph(
        "<b>Honeypot retenu : Cowrie</b> (logiciel libre, à faible et moyenne "
        "interaction), simulant des services SSH (port 2222) et Telnet (port "
        "2223). Il est déployé dans un conteneur Docker, journalise chaque "
        "événement au format JSON (connexions, identifiants testés, commandes "
        "exécutées) et accepte volontairement des identifiants faibles afin de "
        "piéger l'attaquant le plus longtemps possible.", styles["p"]))
    elements.append(tableau(
        [["Attaque prévue", "Description"]] + ATTAQUES,
        [40 * mm, largeur - 40 * mm], styles))

    # 3. Répartition des tâches ----------------------------------------- #
    elements.append(Paragraph("3. Répartition des tâches", styles["h2"]))
    elements.append(Paragraph(
        "Chaque membre intervient sur l'ensemble des phases du projet "
        "(installation, tests, soutenance) ; les rôles ci-dessous précisent "
        "les responsabilités principales de chacun.", styles["p"]))
    elements.append(tableau(
        [["Membre", "Rôle principal", "Périmètre"]] + MEMBRES,
        [28 * mm, 48 * mm, largeur - 76 * mm], styles))

    # 4. Planning prévisionnel ------------------------------------------ #
    elements.append(Paragraph("4. Planning prévisionnel", styles["h2"]))
    elements.append(tableau(
        [["Étape", "Objectif", "Contenu"]] + PLANNING,
        [36 * mm, 44 * mm, largeur - 80 * mm], styles))

    # 5. Outils ---------------------------------------------------------- #
    elements.append(Paragraph("5. Outils utilisés", styles["h2"]))
    elements.append(tableau(
        [["Catégorie", "Outils"]] + OUTILS,
        [36 * mm, largeur - 36 * mm], styles))

    # 6. État d'avancement ------------------------------------------------ #
    elements.append(Paragraph("6. État d'avancement du code et tests réalisés",
                              styles["h2"]))
    elements.append(Paragraph(
        "Le code est versionné sur GitHub (branche de développement "
        "partagée). La chaîne complète a été validée en réel : démarrage du "
        "honeypot et du NIDS, lancement du pentest, collecte des journaux, "
        "génération des analyses et des alertes.", styles["p"]))
    elements.append(tableau(
        [["Élément", "État", "Détails"]] + AVANCEMENT,
        [44 * mm, 20 * mm, largeur - 64 * mm], styles))
    elements.append(Spacer(1, 3 * mm))
    elements.append(Paragraph(
        "<b>Tests réalisés :</b> suite pytest complète (45 tests) couvrant le "
        "moteur de détection, le script de pentest, l'analyse des journaux et "
        "le chiffrement du rapport, avec un scénario de trafic normal "
        "vérifiant l'absence de fausses alertes et un scénario d'attaques "
        "rejoué depuis une capture réseau.", styles["p"]))

    # 7. Travail à venir --------------------------------------------------- #
    elements.append(Paragraph("7. Travail prévu pour la session du 15 décembre",
                              styles["h2"]))
    for item in TRAVAUX_15_DEC:
        elements.append(Paragraph(f"- {item}", styles["p"]))

    doc.build(elements)
    return SORTIE


if __name__ == "__main__":
    chemin = construire_document()
    print(f"Bilan généré : {chemin}")
