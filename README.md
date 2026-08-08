# 🔐 SecureAuth Lab

Mini-laboratoire pédagogique démontrant, sur un même service
d'authentification, **une faille de sécurité classique**, **une attaque
qui l'exploite**, et **une version corrigée avec détection automatique**.

> Projet réalisé pour illustrer ma compréhension des fondamentaux de la
> sécurité applicative, dans le cadre de ma recherche d'alternance en
> cybersécurité / infrastructure réseau.

---

## ⚠️ Avertissement légal et éthique

Ce projet contient un script d'attaque par force brute
(`attacker/brute_force.py`). **Il est conçu pour être utilisé UNIQUEMENT
contre les serveurs de ce dépôt.**

---

## 🎯 Ce que ce projet démontre

| Thème | Où | Ce qui est illustré |
|---|---|---|
| **Faille** | `server_vulnerable.py` | Mots de passe stockés en clair + aucune limitation de tentatives |
| **Attaque** | `attacker/brute_force.py` | Exploitation automatisée de cette faille (brute force) |
| **Sécurisation** | `server_secure.py` | Hash + sel (PBKDF2-HMAC-SHA256), comparaison en temps constant, rate limiting avec blocage temporaire |
| **Détection / réponse** | `defense/ids_monitor.py` | Mini-IDS qui surveille les logs et bloque automatiquement une IP suspecte (blocklist.json) |

L'idée est de montrer, sur un cas volontairement simple, **tout le cycle**
qu'on retrouve en sécurité défensive : une faille existe → elle est
exploitée → on la corrige → on met en place une détection pour repérer
les tentatives d'attaque futures.

## 🏗️ Architecture du projet

```
SecureAuthLab/
├── server_vulnerable.py     # Serveur d'auth SANS protection (port 9001)
├── server_secure.py         # Serveur d'auth SÉCURISÉ (port 9002)
├── attacker/
│   └── brute_force.py       # Script d'attaque par dictionnaire
├── defense/
│   └── ids_monitor.py       # Mini-IDS : surveille les logs, bloque les IP suspectes
├── dashboard/
│   └── dashboard_server.py  # Dashboard web temps réel (logs + blocklist)
├── wordlist.txt              # Liste de mots de passe faibles pour la démo
├── logs/                     # Logs générés à l'exécution (créé automatiquement)
├── .vscode/                  # Config VS Code (extensions recommandées)
├── requirements.txt
└── .gitignore
```

Le dashboard (`dashboard_server.py`) est un serveur web en lecture seule,
écrit uniquement avec la bibliothèque standard `http.server` : il ne fait
que lire les fichiers de logs et la blocklist déjà générés par les autres
scripts pour les afficher joliment dans le navigateur, avec actualisation
automatique toutes les 2 secondes. Il ne modifie jamais la logique de
sécurité elle-même.

Schéma du flux lors d'une attaque contre le serveur vulnérable :

```
attacker/brute_force.py  --(essaie mot de passe après mot de passe)-->  server_vulnerable.py
                                                                                |
                                                                                v
                                                                     logs/auth_vulnerable.log
                                                                                |
                                                                                v
                                                              defense/ids_monitor.py (optionnel)
                                                                                |
                                                                                v
                                                                    logs/blocklist.json
```

Aucune dépendance externe n'est nécessaire : tout est écrit avec la
bibliothèque standard de Python (`socket`, `hashlib`, `hmac`, `threading`,
`json`...).


## 🗺️ Évolutions possibles

- [ ] Ajouter un dashboard web (Flask) affichant les logs et la blocklist en direct
- [ ] Passer le stockage des logs vers une vraie base de données (SQLite)
- [ ] Ajouter des tests unitaires (`pytest`) sur les fonctions de hash et de rate limiting
- [ ] Comparer PBKDF2 avec bcrypt/argon2 (bibliothèque `argon2-cffi`)

## 📄 Licence

Projet distribué sous licence MIT.

## 👤 Auteur

[Brieuc] — en recherche d'alternance en infrastructure réseau /
cybersécurité.
