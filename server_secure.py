#!/usr/bin/env python3
"""
server_secure.py
==================

Version SÉCURISÉE du même service d'authentification que
server_vulnerable.py. Corrige les deux failles démontrées précédemment :

  1. Les mots de passe ne sont jamais stockés en clair : on stocke un
     hash PBKDF2-HMAC-SHA256 salé (technique standard, résistante au
     brute-force offline même en cas de fuite de la base).
  2. Un mécanisme de rate limiting bloque temporairement une IP après
     plusieurs échecs successifs, rendant une attaque par force brute
     beaucoup trop lente pour être exploitable.

Comparez ce fichier à server_vulnerable.py : la logique réseau est
quasi identique, seule la gestion des identifiants change.
"""

from __future__ import annotations  # Compatibilite Python 3.9 pour les annotations de type modernes

import socket
import threading
import hashlib   # Pour générer les hashs de mots de passe (PBKDF2).
import hmac      # Pour comparer les hashs de façon sécurisée (anti timing-attack).
import os        # Pour générer un sel aléatoire cryptographiquement sûr.
import time      # Pour gérer les fenêtres de temps du rate limiting.
from datetime import datetime
from pathlib import Path

# --- Configuration -----------------------------------------------------------
HOST = "127.0.0.1"
PORT = 9002                       # Port différent du serveur vulnérable, pour les faire tourner en parallèle.
LOG_FILE = Path(__file__).parent / "logs" / "auth_secure.log"

# --- Paramètres du rate limiting ---------------------------------------------
MAX_ATTEMPTS = 3        # Nombre d'échecs autorisés avant blocage temporaire.
WINDOW_SECONDS = 60      # Fenêtre de temps (en secondes) sur laquelle on compte les échecs.
LOCKOUT_SECONDS = 30      # Durée du blocage une fois le seuil atteint.

# Dictionnaire en mémoire qui suit, pour chaque IP, la liste des horodatages
# de ses tentatives échouées récentes. Exemple : {"127.0.0.1": [t1, t2, t3]}
failed_attempts: dict[str, list[float]] = {}
# Dictionnaire qui retient, pour chaque IP bloquée, l'heure à laquelle le
# blocage expire. Exemple : {"127.0.0.1": 1723040000.0}
blocked_until: dict[str, float] = {}
# Verrou (lock) pour éviter que deux threads modifient les dicos ci-dessus
# en même temps et créent des incohérences (concurrence).
rate_limit_lock = threading.Lock()


def hash_password(password: str, salt: bytes) -> bytes:
    """
    Transforme un mot de passe en clair en un hash sécurisé.

    PBKDF2-HMAC-SHA256 applique la fonction de hash des dizaines de
    milliers de fois de suite ('iterations'), ce qui ralentit
    volontairement le calcul. Un attaquant qui volerait la base de
    données devrait donc passer énormément de temps de calcul pour
    tester chaque mot de passe candidat (contrairement à un simple
    SHA256 qui se calcule quasi instantanément).
    """
    return hashlib.pbkdf2_hmac(
        "sha256",               # Algorithme de hash sous-jacent.
        password.encode(),      # Le mot de passe doit être en octets, pas en texte.
        salt,                    # Le sel rend chaque hash unique même pour un mot de passe identique.
        100_000,                 # Nombre d'itérations : plus il est élevé, plus c'est lent à casser.
    )


def build_user_store() -> dict[str, dict[str, bytes]]:
    """
    Construit la base d'utilisateurs "sécurisée" au démarrage du serveur.

    En production, ceci viendrait d'une vraie base de données, avec le
    sel et le hash déjà stockés lors de l'inscription de l'utilisateur.
    Ici, on le fait en mémoire pour garder le projet simple à lire.
    """
    users_plaintext_source = {
        "admin": "password123",   # Mêmes mots de passe que la version vulnérable,
        "alice": "alice2024",      # pour bien montrer que seule la PROTECTION change.
    }

    store: dict[str, dict[str, bytes]] = {}
    for username, plain_password in users_plaintext_source.items():
        # os.urandom(16) génère 16 octets aléatoires cryptographiquement sûrs.
        salt = os.urandom(16)
        # On calcule le hash du mot de passe avec ce sel.
        hashed = hash_password(plain_password, salt)
        # On stocke uniquement le sel et le hash — jamais le mot de passe en clair.
        store[username] = {"salt": salt, "hash": hashed}
    return store


# Base d'utilisateurs sécurisée, construite une seule fois au démarrage.
USERS_SECURE = build_user_store()


def log_attempt(ip: str, username: str, success: bool, blocked: bool = False) -> None:
    """Écrit une ligne de log, avec une mention spéciale si l'IP était bloquée."""
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    if blocked:
        status = "BLOCKED"   # La tentative a été rejetée sans même vérifier le mot de passe.
    else:
        status = "OK" if success else "FAIL"
    with LOG_FILE.open("a", encoding="utf-8") as f:
        f.write(f"{timestamp} | {ip} | {username} | {status}\n")


def is_ip_blocked(ip: str) -> bool:
    """Vérifie si une IP est actuellement en période de blocage."""
    with rate_limit_lock:
        # On récupère l'heure d'expiration du blocage pour cette IP (0 si jamais bloquée).
        expiry = blocked_until.get(ip, 0)
        # L'IP est bloquée si l'heure actuelle est encore avant l'expiration.
        return time.time() < expiry


def register_failed_attempt(ip: str) -> None:
    """Enregistre un échec et déclenche un blocage si le seuil est dépassé."""
    with rate_limit_lock:
        now = time.time()
        # On récupère la liste existante des échecs pour cette IP (liste vide si première fois).
        attempts = failed_attempts.setdefault(ip, [])
        # On ajoute l'horodatage de cet échec.
        attempts.append(now)
        # On ne garde que les échecs survenus dans la fenêtre de temps définie
        # (WINDOW_SECONDS), pour ignorer les vieilles tentatives.
        recent_attempts = [t for t in attempts if now - t <= WINDOW_SECONDS]
        failed_attempts[ip] = recent_attempts

        # Si le nombre d'échecs récents dépasse le seuil autorisé...
        if len(recent_attempts) >= MAX_ATTEMPTS:
            # ...on bloque l'IP jusqu'à maintenant + durée de blocage.
            blocked_until[ip] = now + LOCKOUT_SECONDS
            print(f"[SECURE] IP {ip} bloquee {LOCKOUT_SECONDS}s (trop d'echecs).")


def register_success(ip: str) -> None:
    """Réinitialise le compteur d'échecs d'une IP après une connexion réussie."""
    with rate_limit_lock:
        # On efface l'historique des échecs : un succès repart sur une base saine.
        failed_attempts.pop(ip, None)


def check_credentials(username: str, password: str) -> bool:
    """Vérifie les identifiants de façon sécurisée."""
    user_record = USERS_SECURE.get(username)
    if user_record is None:
        # On ne dit jamais "utilisateur inconnu" au client : ça éviterait à un
        # attaquant de savoir quels comptes existent (énumération de comptes).
        return False

    # On recalcule le hash du mot de passe fourni, avec le MÊME sel que celui
    # stocké pour cet utilisateur.
    candidate_hash = hash_password(password, user_record["salt"])

    # hmac.compare_digest() compare deux séquences d'octets en temps CONSTANT,
    # contrairement à '==' qui peut s'arrêter dès le premier octet différent.
    # Cela empêche un attaquant de déduire des informations à partir du temps
    # de réponse du serveur (protection anti timing-attack).
    return hmac.compare_digest(candidate_hash, user_record["hash"])


def handle_client(conn: socket.socket, addr: tuple[str, int]) -> None:
    """Gère une connexion client, avec vérification du rate limiting en amont."""
    client_ip = addr[0]
    try:
        # --- Étape 1 : on vérifie AVANT toute chose si l'IP est bloquée. ---
        if is_ip_blocked(client_ip):
            conn.sendall(b"BLOCKED: trop de tentatives, reessayez plus tard\n")
            log_attempt(client_ip, "?", False, blocked=True)
            return  # On s'arrête ici : on ne vérifie même pas le mot de passe.

        # --- Étape 2 : réception et parsing du message, comme côté vulnérable. ---
        data = conn.recv(1024)
        message = data.decode(errors="ignore").strip()

        if ":" not in message:
            conn.sendall(b"ERROR: format attendu 'username:password'\n")
            return

        username, password = message.split(":", 1)

        # --- Étape 3 : vérification sécurisée des identifiants. ---
        success = check_credentials(username, password)
        log_attempt(client_ip, username, success)

        if success:
            # Un succès réinitialise le compteur d'échecs de cette IP.
            register_success(client_ip)
            conn.sendall(b"OK: authentification reussie\n")
        else:
            # Un échec est comptabilisé et peut déclencher un blocage.
            register_failed_attempt(client_ip)
            conn.sendall(b"FAIL: identifiants invalides\n")
    finally:
        conn.close()


def main() -> None:
    print(f"[SECURE] Serveur demarre sur {HOST}:{PORT}")
    print(f"[SECURE] Rate limiting actif : {MAX_ATTEMPTS} echecs max / {WINDOW_SECONDS}s, "
          f"blocage {LOCKOUT_SECONDS}s.\n")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((HOST, PORT))
        server_socket.listen(20)

        while True:
            conn, addr = server_socket.accept()
            client_thread = threading.Thread(
                target=handle_client, args=(conn, addr), daemon=True
            )
            client_thread.start()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[SECURE] Serveur arrete.")
