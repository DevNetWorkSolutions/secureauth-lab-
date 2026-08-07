#!/usr/bin/env python3
"""
dashboard/dashboard_server.py
================================

Petit serveur web qui affiche, dans le navigateur, une vue en direct de :
  - les dernières lignes des logs d'authentification (vulnerable + secure)
  - le contenu actuel de la blocklist generee par le mini-IDS

Objectif : donner une vitrine VISUELLE au projet pour les démonstrations
(entretien, présentation), sans rien changer à la logique de sécurité
elle-même : ce dashboard ne fait que LIRE les fichiers déjà générés par
server_vulnerable.py, server_secure.py et defense/ids_monitor.py.

Volontairement écrit avec la bibliothèque standard uniquement
(http.server) : aucune installation de paquet nécessaire, donc aucun
risque de blocage le jour d'une démo.

Utilisation :
    python3 dashboard/dashboard_server.py
    -> puis ouvrir http://127.0.0.1:8000 dans le navigateur
"""

from __future__ import annotations  # Compatibilite Python 3.9 pour les annotations de type modernes

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

# --- Configuration -----------------------------------------------------------
HOST = "127.0.0.1"
PORT = 8000
# On calcule le dossier racine du projet (un niveau au-dessus de dashboard/)
# pour retrouver le dossier logs/ quel que soit l'endroit d'où le script est lancé.
PROJECT_ROOT = Path(__file__).parent.parent
LOG_VULNERABLE = PROJECT_ROOT / "logs" / "auth_vulnerable.log"
LOG_SECURE = PROJECT_ROOT / "logs" / "auth_secure.log"
BLOCKLIST_FILE = PROJECT_ROOT / "logs" / "blocklist.json"

# Nombre de lignes de log les plus récentes à afficher dans le dashboard.
MAX_LINES = 18


def read_last_lines(path: Path, max_lines: int) -> list:
    """Lit un fichier et renvoie ses N dernières lignes (les plus récentes)."""
    if not path.exists():
        # Le fichier n'existe pas encore : aucun serveur n'a encore tourné.
        return []
    with path.open(encoding="utf-8") as f:
        lines = [line.strip() for line in f if line.strip()]
    # On garde uniquement les 'max_lines' dernières lignes de la liste.
    return lines[-max_lines:]


def read_blocklist() -> dict:
    """Lit le fichier blocklist.json généré par le mini-IDS."""
    if not BLOCKLIST_FILE.exists():
        return {}
    with BLOCKLIST_FILE.open(encoding="utf-8") as f:
        return json.load(f)


# --- Page HTML principale ----------------------------------------------------
# On garde tout en un seul fichier Python (HTML + CSS + JS inclus) pour que
# le dashboard tienne dans un unique script, simple à lire et à expliquer.
INDEX_HTML = """<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SecureAuth Lab — SOC Monitor</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600;700&family=IBM+Plex+Sans:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
  /* ============================================================
     TOKENS — palette et typographie pensées pour un poste de
     supervision réseau (SOC) : encre bleu-nuit plutôt que noir
     pur, accents signal (cyan) / alerte (corail) / avertissement
     (ambre) plutot que le vert néon générique.
     ============================================================ */
  :root {
    --ink:        #0a0d14;
    --panel:      #10141d;
    --panel-2:    #141924;
    --border:     #1f2531;
    --text:       #dde2ec;
    --muted:      #5f6a7d;
    --muted-2:    #808ba0;
    --safe:       #2dd4a7;
    --danger:     #ff5c7a;
    --warn:       #ffb454;
    --signal:     #4cc9f0;
    --font-ui:    "IBM Plex Sans", -apple-system, sans-serif;
    --font-mono:  "IBM Plex Mono", "SF Mono", Consolas, monospace;
  }

  * { box-sizing: border-box; }

  body {
    margin: 0;
    background: var(--ink);
    color: var(--text);
    font-family: var(--font-ui);
    padding: 32px 40px 60px;
    position: relative;
    overflow-x: hidden;
  }

  /* Léger effet de trame/scanline en fond, très subtil, pour ancrer
     l'esthétique "poste de supervision" sans en faire trop. */
  body::before {
    content: "";
    position: fixed;
    inset: 0;
    pointer-events: none;
    background: repeating-linear-gradient(
      to bottom,
      rgba(76, 201, 240, 0.015) 0px,
      rgba(76, 201, 240, 0.015) 1px,
      transparent 1px,
      transparent 3px
    );
    z-index: 0;
  }

  @media (prefers-reduced-motion: reduce) {
    * { animation: none !important; transition: none !important; }
  }

  /* ============================================================
     HEADER — le radar est l'élément signature de la page : il
     rappelle le balayage réseau (nmap-style) au cœur du projet,
     et pulse en rouge lors d'un blocage détecté.
     ============================================================ */
  header {
    display: flex;
    align-items: center;
    gap: 24px;
    margin-bottom: 32px;
    position: relative;
    z-index: 1;
  }

  .radar {
    position: relative;
    width: 84px;
    height: 84px;
    flex-shrink: 0;
    border-radius: 50%;
    background: radial-gradient(circle, rgba(76,201,240,0.08) 0%, transparent 70%);
    border: 1px solid var(--border);
  }
  .radar::before, .radar::after {
    content: "";
    position: absolute;
    border-radius: 50%;
    border: 1px solid rgba(76, 201, 240, 0.18);
  }
  .radar::before { inset: 14px; }
  .radar::after { inset: 30px; }
  .radar-sweep {
    position: absolute;
    inset: 0;
    border-radius: 50%;
    background: conic-gradient(from 0deg, rgba(76,201,240,0.55), transparent 35%);
    animation: sweep 3.2s linear infinite;
  }
  .radar-core {
    position: absolute;
    top: 50%; left: 50%;
    width: 6px; height: 6px;
    background: var(--signal);
    border-radius: 50%;
    transform: translate(-50%, -50%);
    box-shadow: 0 0 8px 2px rgba(76,201,240,0.7);
  }
  @keyframes sweep { to { transform: rotate(360deg); } }

  .title-block h1 {
    font-family: var(--font-mono);
    font-size: 19px;
    font-weight: 600;
    letter-spacing: 0.02em;
    margin: 0 0 6px 0;
  }
  .status-line {
    display: flex;
    align-items: center;
    gap: 8px;
    font-family: var(--font-mono);
    font-size: 12px;
    color: var(--muted-2);
  }
  .dot {
    width: 7px; height: 7px;
    border-radius: 50%;
    background: var(--safe);
    box-shadow: 0 0 6px 1px rgba(45,212,167,0.7);
    animation: blink 2s ease-in-out infinite;
  }
  @keyframes blink { 0%,100% { opacity: 1; } 50% { opacity: 0.35; } }

  /* ============================================================
     STATS — chiffres en gros, en monospace, façon panneau
     d'instrumentation. Les labels servent d'"eyebrows" techniques.
     ============================================================ */
  .stats {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 1px;
    background: var(--border);
    border: 1px solid var(--border);
    border-radius: 10px;
    overflow: hidden;
    margin-bottom: 28px;
    position: relative;
    z-index: 1;
  }
  .stat {
    background: var(--panel);
    padding: 18px 20px;
  }
  .stat .value {
    font-family: var(--font-mono);
    font-size: 28px;
    font-weight: 700;
    line-height: 1;
    margin-bottom: 6px;
  }
  .stat .label {
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    color: var(--muted);
  }
  .stat.danger .value { color: var(--danger); }
  .stat.warn .value { color: var(--warn); }
  .stat.safe .value { color: var(--safe); }

  /* ============================================================
     PANELS — logs présentés comme de vraies fenêtres de terminal,
     avec liseré de titre façon macOS et police monospace.
     ============================================================ */
  .grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 16px;
    margin-bottom: 16px;
    position: relative;
    z-index: 1;
  }
  .term {
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 10px;
    overflow: hidden;
  }
  .term-bar {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 10px 14px;
    background: var(--panel-2);
    border-bottom: 1px solid var(--border);
    font-family: var(--font-mono);
    font-size: 11.5px;
    color: var(--muted-2);
  }
  .term-bar .dots { display: flex; gap: 6px; margin-right: 6px; }
  .term-bar .dots span {
    width: 9px; height: 9px; border-radius: 50%;
  }
  .term-bar .dots span:nth-child(1) { background: #ff5f57; }
  .term-bar .dots span:nth-child(2) { background: #febc2e; }
  .term-bar .dots span:nth-child(3) { background: #28c840; }

  .term-body {
    padding: 12px 14px;
    max-height: 320px;
    overflow-y: auto;
    font-family: var(--font-mono);
    font-size: 12px;
  }
  .log-line {
    padding: 5px 8px;
    border-radius: 4px;
    margin-bottom: 3px;
    white-space: pre-wrap;
    word-break: break-all;
    border-left: 2px solid transparent;
  }
  .log-line.ok { color: var(--safe); background: rgba(45,212,167,0.06); border-left-color: var(--safe); }
  .log-line.fail { color: var(--danger); background: rgba(255,92,122,0.06); border-left-color: var(--danger); }
  .log-line.blocked { color: var(--warn); background: rgba(255,180,84,0.08); border-left-color: var(--warn); }
  .empty { color: var(--muted); font-size: 12.5px; font-style: italic; }

  /* ============================================================
     BLOCKLIST — table des IP neutralisées par le mini-IDS.
     ============================================================ */
  .blocklist-panel {
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 18px 20px;
    position: relative;
    z-index: 1;
  }
  .blocklist-panel h2 {
    font-size: 12px;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    color: var(--muted);
    margin: 0 0 14px 0;
    font-weight: 600;
  }
  .blocklist-item {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 10px 12px;
    background: rgba(255,92,122,0.05);
    border: 1px solid rgba(255,92,122,0.25);
    border-radius: 8px;
    margin-bottom: 8px;
    font-size: 13px;
    animation: slide-in 0.3s ease;
  }
  @keyframes slide-in {
    from { opacity: 0; transform: translateX(-6px); }
    to { opacity: 1; transform: translateX(0); }
  }
  .blocklist-ip {
    font-family: var(--font-mono);
    color: var(--danger);
    font-weight: 600;
  }
  .blocklist-reason { color: var(--muted-2); font-size: 12px; }

  footer {
    margin-top: 28px;
    font-size: 11.5px;
    color: var(--muted);
    font-family: var(--font-mono);
    position: relative;
    z-index: 1;
  }

  @media (max-width: 760px) {
    .grid { grid-template-columns: 1fr; }
    .stats { grid-template-columns: repeat(2, 1fr); }
  }
</style>
</head>
<body>

  <header>
    <div class="radar" id="radar">
      <div class="radar-sweep"></div>
      <div class="radar-core"></div>
    </div>
    <div class="title-block">
      <h1>SECUREAUTH LAB · SOC MONITOR</h1>
      <div class="status-line">
        <span class="dot"></span>
        <span>SYSTEME ACTIF</span>
        <span style="color: var(--border)">·</span>
        <span>127.0.0.1</span>
        <span style="color: var(--border)">·</span>
        <span id="last-update">en attente</span>
      </div>
    </div>
  </header>

  <div class="stats">
    <div class="stat">
      <div class="value" id="stat-total">0</div>
      <div class="label">Tentatives totales</div>
    </div>
    <div class="stat danger">
      <div class="value" id="stat-fail">0</div>
      <div class="label">Echecs</div>
    </div>
    <div class="stat warn">
      <div class="value" id="stat-blocked-ips">0</div>
      <div class="label">IP neutralisees</div>
    </div>
    <div class="stat safe">
      <div class="value" id="stat-rate">0%</div>
      <div class="label">Taux de blocage</div>
    </div>
  </div>

  <div class="grid">
    <div class="term">
      <div class="term-bar">
        <div class="dots"><span></span><span></span><span></span></div>
        server_vulnerable.py — port 9001
      </div>
      <div class="term-body" id="log-vulnerable">
        <p class="empty">En attente de donnees...</p>
      </div>
    </div>
    <div class="term">
      <div class="term-bar">
        <div class="dots"><span></span><span></span><span></span></div>
        server_secure.py — port 9002
      </div>
      <div class="term-body" id="log-secure">
        <p class="empty">En attente de donnees...</p>
      </div>
    </div>
  </div>

  <div class="blocklist-panel">
    <h2>IP bloquees par le mini-IDS</h2>
    <div id="blocklist"><p class="empty">Aucune IP bloquee pour le moment.</p></div>
  </div>

  <footer>Lecture seule · actualisation automatique toutes les 2 secondes · SecureAuth Lab</footer>

<script>
// Determine la classe CSS (couleur) a appliquer selon le statut
// contenu dans une ligne de log ("OK", "FAIL" ou "BLOCKED").
function classify(line) {
  if (line.includes("| OK")) return "ok";
  if (line.includes("| BLOCKED")) return "blocked";
  return "fail";
}

// Etat global simple pour calculer les statistiques agregees.
let radarPulseTimeout = null;

function pulseRadar() {
  const radar = document.getElementById("radar");
  radar.style.filter = "drop-shadow(0 0 10px rgba(255,92,122,0.8))";
  clearTimeout(radarPulseTimeout);
  radarPulseTimeout = setTimeout(() => { radar.style.filter = "none"; }, 600);
}

async function refreshLogs(type, containerId) {
  const response = await fetch(`/api/logs?type=${type}`);
  const data = await response.json();
  const container = document.getElementById(containerId);

  if (data.lines.length === 0) {
    container.innerHTML = '<p class="empty">Aucune tentative enregistree pour l\\'instant.</p>';
    return { total: 0, fail: 0, ok: 0, blocked: 0 };
  }

  container.innerHTML = data.lines
    .slice()
    .reverse()
    .map(line => `<div class="log-line ${classify(line)}">${line}</div>`)
    .join("");

  let counts = { total: data.lines.length, fail: 0, ok: 0, blocked: 0 };
  for (const line of data.lines) {
    const cls = classify(line);
    counts[cls === "fail" ? "fail" : cls === "ok" ? "ok" : "blocked"]++;
  }
  return counts;
}

async function refreshBlocklist() {
  const response = await fetch("/api/blocklist");
  const data = await response.json();
  const container = document.getElementById("blocklist");
  const ips = Object.keys(data);

  if (ips.length > 0) pulseRadar();

  if (ips.length === 0) {
    container.innerHTML = '<p class="empty">Aucune IP bloquee pour le moment.</p>';
    return 0;
  }

  container.innerHTML = ips.map(ip => `
    <div class="blocklist-item">
      <span class="blocklist-ip">${ip}</span>
      <span class="blocklist-reason">${data[ip].reason} — bloque a ${data[ip].blocked_at}</span>
    </div>
  `).join("");
  return ips.length;
}

async function refreshAll() {
  const [vuln, secure, blockedCount] = await Promise.all([
    refreshLogs("vulnerable", "log-vulnerable"),
    refreshLogs("secure", "log-secure"),
    refreshBlocklist(),
  ]);

  const total = vuln.total + secure.total;
  const fails = vuln.fail + secure.fail + vuln.blocked + secure.blocked;
  const rate = total > 0 ? Math.round((fails / total) * 100) : 0;

  document.getElementById("stat-total").textContent = total;
  document.getElementById("stat-fail").textContent = fails;
  document.getElementById("stat-blocked-ips").textContent = blockedCount;
  document.getElementById("stat-rate").textContent = rate + "%";

  const now = new Date();
  document.getElementById("last-update").textContent =
    "maj " + now.toLocaleTimeString("fr-FR");
}

refreshAll();
setInterval(refreshAll, 2000);
</script>
</body>
</html>
"""


class DashboardHandler(BaseHTTPRequestHandler):
    """Gère les requêtes HTTP entrantes du navigateur."""

    def _send_json(self, payload: dict) -> None:
        """Fonction utilitaire pour renvoyer une réponse au format JSON."""
        body = json.dumps(payload).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_html(self, html: str) -> None:
        """Fonction utilitaire pour renvoyer une réponse HTML."""
        body = html.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        """Routeur très simple basé sur le chemin de l'URL demandée."""
        # self.path contient le chemin ET les paramètres de requête (après '?').
        if self.path == "/" or self.path == "/index.html":
            self._send_html(INDEX_HTML)

        elif self.path.startswith("/api/logs"):
            # On détermine quel fichier de log lire selon le paramètre '?type='.
            if "type=vulnerable" in self.path:
                lines = read_last_lines(LOG_VULNERABLE, MAX_LINES)
            else:
                lines = read_last_lines(LOG_SECURE, MAX_LINES)
            self._send_json({"lines": lines})

        elif self.path.startswith("/api/blocklist"):
            self._send_json(read_blocklist())

        else:
            # Toute autre route renvoie une 404 classique.
            self.send_response(404)
            self.end_headers()

    def log_message(self, format: str, *args) -> None:
        # On désactive les logs par défaut de http.server (trop verbeux),
        # pour garder un terminal propre pendant la démo.
        pass


def main() -> None:
    print(f"[DASHBOARD] Serveur demarre : http://{HOST}:{PORT}")
    print("[DASHBOARD] Ouvrez cette adresse dans votre navigateur.\n")
    server = ThreadingHTTPServer((HOST, PORT), DashboardHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[DASHBOARD] Serveur arrete.")


if __name__ == "__main__":
    main()
