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
contre les serveurs de ce dépôt, en local (127.0.0.1).**

Utiliser ce type de script contre un système que vous ne possédez pas et
pour lequel vous n'avez pas d'autorisation écrite est **illégal** (en
France : articles 323-1 et suivants du Code pénal). Ce projet a un but
strictement pédagogique.

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

## 📦 Installation

**Prérequis :** Python 3.10+ et VS Code avec l'extension Python (proposée
automatiquement à l'ouverture du dossier, voir `.vscode/extensions.json`).

```bash
git clone https://github.com/<DevNetWorkSolutions>/secureauth-lab.git
cd secureauth-lab
```

Aucune installation de paquet n'est nécessaire (`requirements.txt` est
volontairement vide, prêt pour d'éventuelles évolutions).

## 🧪 Démonstration pas à pas

Ouvrez **4 terminaux** dans VS Code (menu *Terminal → Nouveau terminal*,
ou clic sur le "+" dans le panneau terminal).

### Partie 0 — Lancer le dashboard visuel

**Terminal 4** :
```bash
python3 dashboard/dashboard_server.py
```
Puis ouvrez **http://127.0.0.1:8000** dans votre navigateur et laissez
l'onglet ouvert : il affichera en direct les tentatives de connexion et
les IP bloquées au fur et à mesure des étapes suivantes.

### Partie 1 — Démontrer la faille

**Terminal 1** — lancer le serveur vulnérable :
```bash
python3 server_vulnerable.py
```

**Terminal 2** — lancer l'attaque par force brute contre lui :
```bash
python3 attacker/brute_force.py --port 9001 --user admin
```

Vous devriez voir le script trouver le mot de passe `password123` en
quelques tentatives, quasi instantanément : **aucune protection ne
ralentit l'attaquant.**

### Partie 2 — Démontrer la protection

**Terminal 1** (nouveau, ou arrêtez le précédent avec Ctrl+C) :
```bash
python3 server_secure.py
```

**Terminal 2** — même attaque, mais contre le serveur sécurisé :
```bash
python3 attacker/brute_force.py --port 9002 --user admin
```

Cette fois, après 3 échecs, le serveur répond `BLOCKED` pendant 30
secondes : l'attaque est stoppée net, même si le mot de passe correct
se trouve plus loin dans la liste.

### Partie 3 — Démontrer la détection automatique

Relancez une attaque contre le serveur **vulnérable** (Partie 1), puis,
dans un **Terminal 3**, lancez le mini-IDS pendant que l'attaque tourne :
```bash
python3 defense/ids_monitor.py --log logs/auth_vulnerable.log --threshold 5 --window 60
```

Vous verrez le mini-IDS compter les échecs en temps réel et, une fois le
seuil dépassé, afficher une alerte et écrire l'IP attaquante dans
`logs/blocklist.json` — exactement le principe utilisé par des outils
comme Fail2Ban en environnement réel.

## 🧠 Concepts clés à retenir

- **Stockage de mots de passe** : jamais en clair → toujours hashé avec
  un algorithme lent et salé (PBKDF2, bcrypt, argon2).
- **Sel (salt)** : valeur aléatoire unique par utilisateur, empêche deux
  mots de passe identiques d'avoir le même hash, et rend inefficaces les
  attaques par table précalculée (rainbow tables).
- **Comparaison en temps constant** (`hmac.compare_digest`) : évite de
  laisser fuiter de l'information via le temps de réponse du serveur.
- **Rate limiting** : ralentit ou bloque un attaquant après un certain
  nombre d'échecs, rendant une attaque par force brute impraticable.
- **Détection (IDS/IPS)** : même avec de bonnes protections, surveiller
  les logs permet de repérer un comportement suspect et de réagir
  (alerte, blocage, investigation).

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
