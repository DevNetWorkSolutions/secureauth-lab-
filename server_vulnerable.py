#!/usr/bin/env python3
"""
server_vulnerable.py
=====================

Serveur d'authentification VOLONTAIREMENT vulnérable.

But pédagogique : montrer concrètement DEUX failles très courantes en
sécurité applicative :

  1. Stockage des mots de passe en clair (aucun hash, aucun sel).
  2. Absence de limitation du nombre de tentatives (pas de rate limiting)
     => le service est vulnérable à une attaque par force brute.

⚠️  Ne JAMAIS reproduire ces pratiques dans un vrai projet. Ce fichier
existe uniquement pour être comparé à server_secure.py et pour servir
de cible d'entraînement à attacker/brute_force.py, EN LOCAL uniquement
(127.0.0.1).
"""

from __future__ import annotations  # Compatibilite Python 3.9 pour les annotations de type modernes

# --- Imports ---------------------------------------------------------------
# 'socket' : bibliothèque standard permettant de créer un serveur réseau TCP.
import socket
# 'threading' : permet de gérer plusieurs connexions clients en parallèle.
import threading
# 'datetime' : pour horodater chaque tentative de connexion dans les logs.
from datetime import datetime
# 'pathlib.Path' : manipulation de chemins de fichiers de façon portable.
from pathlib import Path

# --- Configuration du serveur -----------------------------------------------
HOST = "127.0.0.1"      # On n'écoute que sur la machine locale (jamais 0.0.0.0 pour ce lab).
PORT = 9001              # Port choisi arbitrairement pour ce service de démo.
LOG_FILE = Path(__file__).parent / "logs" / "auth_vulnerable.log"  # Fichier de log dédié.

# --- "Base de données" des utilisateurs -------------------------------------
# ⚠️ FAILLE N°1 : les mots de passe sont stockés EN CLAIR dans un simple
# dictionnaire Python. Si ce fichier ou cette mémoire fuitait (ex: dump
# mémoire, fichier de config exposé), tous les mots de passe seraient
# immédiatement lisibles par un attaquant.
USERS_PLAINTEXT = {
    "admin": "password123",   # Mot de passe faible ET stocké en clair : double faute.
    "alice": "alice2024",
}


def log_attempt(ip: str, username: str, success: bool) -> None:
    """Écrit une ligne de log pour chaque tentative de connexion."""
    # On s'assure que le dossier logs/ existe avant d'écrire dedans.
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    # On formate un horodatage lisible (année-mois-jour heure:minute:seconde).
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    # "OK" si succès, "FAIL" si échec : facilite le parsing par le mini-IDS.
    status = "OK" if success else "FAIL"
    # On ouvre le fichier en mode "append" (ajout à la fin) pour ne rien écraser.
    with LOG_FILE.open("a", encoding="utf-8") as f:
        # Format volontairement simple : timestamp | ip | user | status
        f.write(f"{timestamp} | {ip} | {username} | {status}\n")


def check_credentials(username: str, password: str) -> bool:
    """
    Vérifie les identifiants.

    ⚠️ FAILLE N°2 : comparaison directe avec '==' d'une chaîne en clair.
    En plus du stockage en clair, cette comparaison n'est pas protégée
    contre les attaques par mesure de temps (timing attack) : le temps de
    réponse peut varier légèrement selon le nombre de caractères corrects,
    ce qui peut théoriquement aider un attaquant à deviner le mot de passe
    caractère par caractère.
    """
    # .get() renvoie None si le username n'existe pas, évitant une KeyError.
    stored_password = USERS_PLAINTEXT.get(username)
    # Si l'utilisateur n'existe pas, on renvoie False directement.
    if stored_password is None:
        return False
    # Comparaison naïve et non protégée contre les timing attacks.
    return stored_password == password


def handle_client(conn: socket.socket, addr: tuple[str, int]) -> None:
    """Gère une connexion client unique (une tentative de login)."""
    # 'addr' est un tuple (ip, port) ; on ne garde que l'IP pour les logs.
    client_ip = addr[0]
    try:
        # On reçoit jusqu'à 1024 octets envoyés par le client.
        data = conn.recv(1024)
        # On décode les octets reçus en texte, en ignorant les erreurs d'encodage.
        message = data.decode(errors="ignore").strip()

        # ⚠️ AUCUNE limitation de tentatives ici : un script peut boucler
        # à l'infini sur cette fonction sans jamais être bloqué => brute force possible.

        # Le protocole attendu est très simple : "username:password"
        if ":" not in message:
            # Message mal formé : on renvoie une erreur générique.
            conn.sendall(b"ERROR: format attendu 'username:password'\n")
            return

        # On sépare le message en (username, password) au premier ':' rencontré.
        username, password = message.split(":", 1)

        # On vérifie les identifiants avec la fonction définie plus haut.
        success = check_credentials(username, password)

        # On journalise systématiquement la tentative, succès ou échec.
        log_attempt(client_ip, username, success)

        # On renvoie une réponse claire au client selon le résultat.
        if success:
            conn.sendall(b"OK: authentification reussie\n")
        else:
            conn.sendall(b"FAIL: identifiants invalides\n")
    finally:
        # On ferme systématiquement la connexion, même en cas d'erreur.
        conn.close()


def main() -> None:
    """Point d'entrée : démarre le serveur et accepte les connexions en boucle."""
    print(f"[VULNERABLE] Serveur demarre sur {HOST}:{PORT}")
    print("[VULNERABLE] Aucune protection anti brute-force active.\n")

    # AF_INET = on utilise IPv4 ; SOCK_STREAM = on utilise le protocole TCP.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        # Permet de relancer le serveur rapidement sans erreur "port déjà utilisé".
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # On lie le socket à l'adresse et au port définis plus haut.
        server_socket.bind((HOST, PORT))
        # On passe le socket en mode écoute, avec une file d'attente de 20 connexions.
        server_socket.listen(20)

        # Boucle infinie : le serveur tourne tant qu'on ne l'arrête pas (Ctrl+C).
        while True:
            # accept() bloque jusqu'à ce qu'un client se connecte.
            conn, addr = server_socket.accept()
            # Chaque client est géré dans un thread séparé pour ne pas bloquer les autres.
            client_thread = threading.Thread(
                target=handle_client, args=(conn, addr), daemon=True
            )
            client_thread.start()


# Ce bloc ne s'exécute que si on lance directement ce fichier
# (et non si on l'importe depuis un autre script).
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        # Arrêt propre du serveur avec Ctrl+C, sans afficher de trace d'erreur moche.
        print("\n[VULNERABLE] Serveur arrete.")
