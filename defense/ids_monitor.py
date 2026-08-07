#!/usr/bin/env python3
"""
defense/ids_monitor.py
========================

Mini-IDS (Intrusion Detection System) très simplifié.

Ce script surveille en temps réel un fichier de log d'authentification
(généré par server_vulnerable.py ou server_secure.py) et détecte les
comportements suspects : trop d'échecs de connexion pour une même IP
sur une courte période.

Quand le seuil est dépassé, l'IP est ajoutée à un fichier blocklist.json,
qui simule la réaction automatique d'un pare-feu ou d'un IPS (Intrusion
Prevention System) en environnement réel.

C'est ce genre de mécanisme (simplifié ici) qui existe dans des outils
professionnels comme Fail2Ban, ou dans les règles de détection d'un SIEM.

Utilisation :
    python3 defense/ids_monitor.py --log logs/auth_vulnerable.log
    python3 defense/ids_monitor.py --log logs/auth_secure.log
"""

from __future__ import annotations  # Compatibilite Python 3.9 pour les annotations de type modernes

import argparse
import json
import time
from collections import defaultdict, deque
from datetime import datetime
from pathlib import Path

# --- Paramètres de détection (peuvent être ajustés en ligne de commande) ---
DEFAULT_THRESHOLD = 5        # Nombre d'échecs qui déclenche une alerte.
DEFAULT_WINDOW_SECONDS = 60   # Fenêtre de temps sur laquelle on compte les échecs.


def parse_log_line(line: str) -> tuple[str, str, str] | None:
    """
    Parse une ligne de log au format :
        "2026-08-07 17:20:01 | 127.0.0.1 | admin | FAIL"

    Renvoie un tuple (timestamp_str, ip, status), ou None si la ligne
    est mal formée (ex: ligne vide, ligne corrompue).
    """
    parts = [p.strip() for p in line.split("|")]
    if len(parts) != 4:
        return None
    timestamp_str, ip, _username, status = parts
    return timestamp_str, ip, status


def load_blocklist(path: Path) -> dict:
    """Charge la blocklist existante depuis le disque, ou en crée une vide."""
    if path.exists():
        with path.open(encoding="utf-8") as f:
            return json.load(f)
    return {}


def save_blocklist(path: Path, blocklist: dict) -> None:
    """Sauvegarde la blocklist sur le disque au format JSON, joliment indenté."""
    with path.open("w", encoding="utf-8") as f:
        json.dump(blocklist, f, indent=2, ensure_ascii=False)


def monitor(log_path: Path, blocklist_path: Path, threshold: int, window_seconds: int) -> None:
    """
    Boucle principale de surveillance.

    Cette fonction lit le fichier de log en continu (comme la commande
    Unix 'tail -f'), analyse chaque nouvelle ligne, et déclenche une
    alerte + blocage si une IP dépasse le seuil d'échecs autorisés.
    """
    print(f"[IDS] Surveillance du fichier : {log_path}")
    print(f"[IDS] Seuil d'alerte : {threshold} echecs / {window_seconds}s\n")

    # 'defaultdict(deque)' crée automatiquement une file vide pour chaque
    # nouvelle IP rencontrée. Une deque (double-ended queue) permet d'ajouter
    # et de retirer des éléments efficacement des deux côtés.
    failed_timestamps: dict[str, deque] = defaultdict(deque)

    # On charge la blocklist existante (pour ne pas repartir de zéro si le
    # script a déjà tourné avant).
    blocklist = load_blocklist(blocklist_path)

    # On s'assure que le fichier de log existe avant de commencer à le lire.
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_path.touch(exist_ok=True)

    with log_path.open(encoding="utf-8") as f:
        # On se place directement à la fin du fichier : on ne veut surveiller
        # que les NOUVELLES lignes à partir du lancement du script.
        f.seek(0, 2)  # 2 = SEEK_END : se positionner à la fin du fichier.

        while True:
            line = f.readline()

            if not line:
                # Pas de nouvelle ligne pour l'instant : on attend un peu
                # avant de réessayer, pour ne pas monopoliser le processeur.
                time.sleep(0.5)
                continue

            parsed = parse_log_line(line)
            if parsed is None:
                continue  # Ligne mal formée : on l'ignore et on continue.

            timestamp_str, ip, status = parsed

            # On ne s'intéresse qu'aux échecs et aux tentatives déjà bloquées.
            if status not in ("FAIL", "BLOCKED"):
                continue

            now = time.time()
            # On ajoute l'horodatage de cet échec à la file de cette IP.
            failed_timestamps[ip].append(now)

            # On retire de la file toutes les tentatives trop anciennes
            # (en dehors de la fenêtre de temps surveillée).
            while failed_timestamps[ip] and now - failed_timestamps[ip][0] > window_seconds:
                failed_timestamps[ip].popleft()

            recent_count = len(failed_timestamps[ip])
            print(f"[IDS] Echec detecte pour {ip} ({recent_count}/{threshold} sur {window_seconds}s)")

            # Si le nombre d'échecs récents dépasse le seuil ET que l'IP
            # n'est pas déjà dans la blocklist, on déclenche une alerte.
            if recent_count >= threshold and ip not in blocklist:
                alert_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                print(f"\n[IDS] 🚨 ALERTE : IP {ip} depasse le seuil ({recent_count} echecs) !")
                print(f"[IDS] -> Ajout de {ip} a la blocklist.\n")

                # On enregistre l'IP bloquée avec la raison et l'horodatage,
                # pour garder une trace exploitable (utile en entretien pour
                # expliquer la démarche d'investigation a posteriori).
                blocklist[ip] = {
                    "blocked_at": alert_time,
                    "reason": f"{recent_count} echecs en moins de {window_seconds}s",
                }
                save_blocklist(blocklist_path, blocklist)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Mini-IDS : surveille un fichier de log et bloque les IP suspectes."
    )
    parser.add_argument("--log", required=True, help="Chemin du fichier de log a surveiller")
    parser.add_argument(
        "--blocklist",
        default=str(Path(__file__).parent.parent / "logs" / "blocklist.json"),
        help="Chemin du fichier blocklist genere",
    )
    parser.add_argument("--threshold", type=int, default=DEFAULT_THRESHOLD, help="Nombre d'echecs avant blocage")
    parser.add_argument("--window", type=int, default=DEFAULT_WINDOW_SECONDS, help="Fenetre de temps en secondes")
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    monitor(
        log_path=Path(args.log),
        blocklist_path=Path(args.blocklist),
        threshold=args.threshold,
        window_seconds=args.window,
    )


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[IDS] Surveillance arretee.")
