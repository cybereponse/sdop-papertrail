"""
Export SIEM — détection, jamais preuve (EX-6).

Deux flux, deux rôles, et la distinction doit rester nette :

                  Ledger                    Flux SIEM
    Rôle          preuve opposable          détection, corrélation
    Écriture      fail-closed (503)         best-effort, jamais bloquant
    Support       fichier chaîné + digest   une ligne JSON par événement

Faire échouer une requête parce que le collecteur est injoignable transformerait
le SIEM en levier de déni de service : il suffirait de faire tomber le collecteur
pour faire tomber SDOP. `ARCHITECTURE.md` l'exige déjà — « ne jamais
présenter Loki comme journal opposable ».

Transport : un fichier, pas un flux réseau
-------------------------------------------
Dans un réseau segmenté, ouvrir un flux de journalisation (syslog) est une
décision d'architecture, pas un réglage : aucun flux n'est donc supposé.

SDOP écrit ses événements en JSON Lines dans un fichier, que l'agent local
ingère (décodeur JSON natif de la plupart des agents, aucune configuration
supplémentaire). Zéro flux à ouvrir, zéro dépendance au collecteur.

Le jour où un transport réseau sera autorisé, seul ce module change.
"""
import json
import os
import threading
from datetime import datetime, timezone

#: Chemin du journal d'événements. Vide = export désactivé (développement).
PATH = os.environ.get("SDOP_SIEM_PATH", "")

#: Nom du produit dans les événements, pour les règles de corrélation.
PRODUCT = os.environ.get("SDOP_SIEM_PRODUCT", "sdop")

ENABLED = bool(PATH)

_verrou = threading.Lock()

#: Événements qui méritent une attention immédiate côté détection. Le niveau
#: n'est pas cosmétique : il pilote les règles d'alerte du collecteur.
SEVERITES = {
    "access_denied": "warning",
    "publish_denied": "warning",
    "tile_denied": "warning",
    "link_failed": "warning",
    "link_denied": "warning",
    "extend_denied": "warning",
    "withdraw_denied": "warning",
    "integrity_failed": "critical",
    "sealed_access_attempt": "critical",
    "ledger_unavailable": "critical",
    "containment_enabled": "critical",
    "link_revoked": "notice",
    "document_withdrawn": "notice",
    "document_sealed": "notice",
}


def emit(entry: dict, *, ledger_hash: str | None = None,
         ledger_error: str | None = None) -> None:
    """Écrit un événement. N'échoue JAMAIS vers l'appelant.

    `ledger_error` est renseigné quand l'inscription au ledger a échoué : c'est
    précisément l'événement que la détection doit voir passer, alors même que la
    requête, elle, est refusée.
    """
    if not ENABLED:
        return
    evenement = {
        "@timestamp": datetime.now(timezone.utc).isoformat(),
        "product": PRODUCT,
        "event": entry.get("event", "unknown"),
        "severity": SEVERITES.get(entry.get("event", ""), "info"),
        "actor": entry.get("actor"),
        "doc_id": entry.get("doc_id"),
        "tlp": entry.get("tlp"),
        "ip": entry.get("ip"),
        "view_id": entry.get("view_id"),
        "ledger_hash": ledger_hash,
    }
    if ledger_error:
        evenement["ledger_error"] = ledger_error
    # Champs applicatifs restants, sans écraser les champs normalisés.
    for cle, valeur in entry.items():
        if cle not in evenement and cle not in ("manifest", "signature"):
            evenement[cle] = valeur

    ligne = json.dumps({k: v for k, v in evenement.items() if v is not None},
                       ensure_ascii=False, sort_keys=True) + "\n"
    try:
        os.makedirs(os.path.dirname(PATH) or ".", exist_ok=True)
        with _verrou, open(PATH, "a", encoding="utf-8") as f:
            f.write(ligne)
    except OSError:
        # Volontairement silencieux : un collecteur indisponible ne doit jamais
        # dégrader le service. La preuve, elle, est au ledger.
        pass
